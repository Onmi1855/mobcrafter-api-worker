export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ----------------------------
    // CORS
    // ----------------------------
    const corsHeaders = (req) => {
      const origin = req.headers.get("Origin") || "*";
      return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        // CF Access のメールヘッダ等も許可
        "Access-Control-Allow-Headers":
          "Content-Type, Authorization, Cf-Access-Authenticated-User-Email, CF-Access-Authenticated-User-Email, cf-access-authenticated-user-email, Cf-Access-Jwt-Assertion, CF-Access-Jwt-Assertion, cf-access-jwt-assertion",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin",
      };
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const json = (obj, status = 200, headers = {}) =>
      new Response(JSON.stringify(obj, null, 2), {
        status,
        headers: {
          ...headers,
          "Content-Type": "application/json; charset=utf-8",
        },
      });

    const safeFilename = (name) => {
      const s = String(name || "file")
        .replace(/[\\\/:*?"<>|]+/g, "_")
        .replace(/\s+/g, "_")
        .slice(0, 120);
      return s || "file";
    };

    const nowIso = () => new Date().toISOString();

    // ----------------------------
    // Auth helpers (Cloudflare Access)
    // ----------------------------
    const getAccessEmail = (req) => {
      const candidates = [
        "Cf-Access-Authenticated-User-Email",
        "CF-Access-Authenticated-User-Email",
        "cf-access-authenticated-user-email",
      ];
      for (const k of candidates) {
        const v = req.headers.get(k);
        if (v && String(v).includes("@")) return String(v).trim().toLowerCase();
      }
      return null;
    };

    const isAdminEmail = (email) => {
      if (!email) return false;
      const raw = String(env.ADMIN_EMAILS || env.ADMIN_EMAIL || "").trim();
      if (!raw) return false;
      const allow = raw
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      return allow.includes(email);
    };

    const requireAdmin = (req) => {
      const email = getAccessEmail(req);
      if (!email || !isAdminEmail(email)) return { ok: false, status: 401, email };
      return { ok: true, status: 200, email };
    };

    const requireUser = (req) => {
      const email = getAccessEmail(req);
      if (!email) return { ok: false, status: 401, email: null };
      return { ok: true, status: 200, email };
    };

    const canOwnerOrAdmin = (email, rowAuthorEmail) => {
      if (!email) return false;
      if (isAdminEmail(email)) return true;
      const owner = String(rowAuthorEmail || "").trim().toLowerCase();
      return owner && owner === email;
    };

    // ----------------------------
    // unitId rewrite（確定仕様）
    // ----------------------------
    const rewriteUnitId = (obj, unitId) => {
      if (obj && typeof obj === "object") {
        obj.id = unitId;
        obj.unitId = unitId;
      }
      return obj;
    };

    const readR2JsonTextAndRewrite = async (jsonKey, unitId) => {
      const obj = await env.UPLOADS_BUCKET.get(jsonKey);
      if (!obj) return { ok: false, error: "file_missing" };

      const text = await obj.text();
      let bodyText = text;
      try {
        const j = JSON.parse(text);
        if (j && typeof j === "object") {
          rewriteUnitId(j, unitId);
          bodyText = JSON.stringify(j, null, 2);
        }
      } catch (_) {
        bodyText = text;
      }
      return { ok: true, text: bodyText };
    };

    // ログイン導線（Access通過後に next へ戻す）
    if (request.method === "GET" && url.pathname === "/api/login") {
      const next = url.searchParams.get("next") || "/";
      const safeNext = (next.startsWith("/") && !next.startsWith("//")) ? next : "/";
      const to = new URL(safeNext, url.origin).toString(); // ★絶対URL化
      return Response.redirect(to, 302);
    }

    // ----------------------------
    // Health
    // ----------------------------
    if (url.pathname === "/api/health" || url.pathname === "/health") {
      return json({ ok: true }, 200, corsHeaders(request));
    }

    // ----------------------------
    // Debug: Cloudflare Access headers
    // ----------------------------
    if (url.pathname === "/api/debug/access") {
      const email =
        request.headers.get("Cf-Access-Authenticated-User-Email") ||
        request.headers.get("CF-Access-Authenticated-User-Email") ||
        request.headers.get("cf-access-authenticated-user-email") ||
        null;

      const jwt =
        request.headers.get("Cf-Access-Jwt-Assertion") ||
        request.headers.get("CF-Access-Jwt-Assertion") ||
        request.headers.get("cf-access-jwt-assertion") ||
        null;

      return json(
        {
          ok: true,
          email,
          has_jwt: Boolean(jwt),
          admin_env: String(env.ADMIN_EMAILS || env.ADMIN_EMAIL || ""),
          path: url.pathname,
        },
        200,
        corsHeaders(request)
      );
    }

    // ----------------------------
    // whoami（ログイン確認/管理者判定）
    // - ?next=/path があれば、ログイン済みのときだけ 302 で戻す
    // - それ以外は JSON を返す（フロントの状態表示用）
    // ----------------------------
    if (request.method === "GET" && url.pathname === "/api/whoami") {
      try {
        const email = getAccessEmail(request);
        const payload = {
          ok: true,
          email: email || null,
          is_admin: email ? isAdminEmail(email) : false
        };

        const next = url.searchParams.get("next");

        if (next) {
          const safeNext =
            next.startsWith("/") && !next.startsWith("//") ? next : "/";

          if (email) {
            const to = new URL(safeNext, url.origin).toString(); // ★絶対URL化
            return new Response("", { status: 302, headers: { Location: to } });
          }
          return json(payload, 200, corsHeaders(request));
        }

        return json(payload, 200, corsHeaders(request));
      } catch (e) {
        return json(
          { ok: false, error: "whoami_exception", message: String(e?.message || e) },
          500,
          corsHeaders(request)
        );
      }
    }

    // =========================================================
    // PUBLIC
    // =========================================================

    // 公開一覧（approvedのみ） + pagination/q/sort（後方互換）
    if (request.method === "GET" && url.pathname === "/api/public/submissions") {
      // パラメータ無しなら従来挙動（LIMIT 100固定）
      const hasAnyParam =
        url.searchParams.has("page") ||
        url.searchParams.has("page_size") ||
        url.searchParams.has("limit") ||
        url.searchParams.has("offset") ||
        url.searchParams.has("q") ||
        url.searchParams.has("sort");

      if (!hasAnyParam) {
        const { results } = await env.SUBMISSIONS_DB.prepare(
          `SELECT
              id,
              submission_no,
              unit_id,
              title,
              description,
              tags,
              author_name,
              created_at,
              mod_version,
              download_count,
              thumb_mode,
              thumb_screen_id
           FROM submissions
           WHERE status='approved' AND deleted_at IS NULL
           ORDER BY created_at DESC
           LIMIT 100`
        ).all();

        return json({ items: results }, 200, corsHeaders(request));
      }

      // ---- paging ----
      const clampInt = (v, def, min, max) => {
        const n = Number(v);
        if (!Number.isFinite(n)) return def;
        const i = Math.floor(n);
        return Math.max(min, Math.min(max, i));
      };

      // page/page_size 優先（limit/offset も互換で許可）
      const pageSize = clampInt(url.searchParams.get("page_size") ?? url.searchParams.get("limit"), 20, 1, 50);

      let page = clampInt(url.searchParams.get("page"), 1, 1, 10_000_000);
      let offset = clampInt(url.searchParams.get("offset"), (page - 1) * pageSize, 0, 1_000_000_000);

      // page 指定がある場合は offset を page から確定
      if (url.searchParams.has("page")) {
        offset = (page - 1) * pageSize;
      } else {
        // offset 指定の場合は page を推定（返却メタ用）
        page = Math.floor(offset / pageSize) + 1;
      }

      const qraw = String(url.searchParams.get("q") || "").trim().toLowerCase();
      const qlike = qraw ? `%${qraw}%` : null;

      const sort = String(url.searchParams.get("sort") || "new").trim().toLowerCase();
      let orderBy = `created_at DESC, id DESC`;
      if (sort === "dl") orderBy = `download_count DESC, created_at DESC, id DESC`;
      else if (sort === "name") orderBy = `title ASC, created_at DESC, id DESC`;

      // WHERE
      let where = `status='approved' AND deleted_at IS NULL`;
      const binds = [];

      if (qlike) {
        where += `
          AND (
            LOWER(COALESCE(title,'')) LIKE ?
            OR LOWER(COALESCE(description,'')) LIKE ?
            OR LOWER(COALESCE(tags,'')) LIKE ?
            OR LOWER(COALESCE(author_name,'')) LIKE ?
            OR LOWER(COALESCE(unit_id,'')) LIKE ?
            OR LOWER(COALESCE(id,'')) LIKE ?
          )
        `;
        binds.push(qlike, qlike, qlike, qlike, qlike, qlike);
      }

      // total_count
      const countRow = await env.SUBMISSIONS_DB.prepare(
        `SELECT COUNT(*) AS cnt FROM submissions WHERE ${where}`
      ).bind(...binds).first();

      const totalCount = Number(countRow?.cnt || 0);
      const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

      // page が範囲外でも壊れないように丸める
      page = Math.max(1, Math.min(totalPages, page));
      offset = (page - 1) * pageSize;

      const { results } = await env.SUBMISSIONS_DB.prepare(
        `SELECT
            id,
            submission_no,
            unit_id,
            title,
            description,
            tags,
            author_name,
            created_at,
            mod_version,
            download_count,
            thumb_mode,
            thumb_screen_id
         FROM submissions
         WHERE ${where}
         ORDER BY ${orderBy}
         LIMIT ? OFFSET ?`
      ).bind(...binds, pageSize, offset).all();

      return json(
        {
          items: results || [],
          page,
          page_size: pageSize,
          total_count: totalCount,
          total_pages: totalPages,
          sort,
          q: qraw || ""
        },
        200,
        corsHeaders(request)
      );
    }

    // 公開：submission id で1件取得（approvedのみ）
    // GET /api/public/submissions/:id
    const publicMetaById = url.pathname.match(/^\/api\/public\/submissions\/([^\/]+)$/);
    if (request.method === "GET" && publicMetaById) {
      const id = publicMetaById[1];

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT
            id,
            submission_no,
            unit_id,
            status,
            title,
            description,
            tags,
            author_name,
            author_email,
            mc_version,
            mod_version,
            created_at,
            updated_at,
            download_count,
            thumb_mode,
            thumb_screen_id
         FROM submissions
         WHERE id=? AND deleted_at IS NULL
         LIMIT 1`
      ).bind(id).first();

      if (!row) return json({ error: "not_found" }, 404, corsHeaders(request));
      if (row.status !== "approved") return json({ error: "not_approved" }, 403, corsHeaders(request));

      return json(row, 200, corsHeaders(request));
    }

    // 詳細ページ用：submission_no で1件取得（approvedのみ）
    // GET /api/public/u/:no
    const publicU = url.pathname.match(/^\/api\/public\/u\/(\d+)$/);
    if (request.method === "GET" && publicU) {
      const no = Number(publicU[1]);
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT
            id,
            submission_no,
            unit_id,
            status,
            title,
            description,
            tags,
            author_name,
            author_email,
            mc_version,
            mod_version,
            created_at,
            updated_at,
            download_count,
            thumb_mode,
            thumb_screen_id
         FROM submissions
         WHERE submission_no=? AND deleted_at IS NULL
         LIMIT 1`
      ).bind(no).first();

      if (!row) return json({ error: "not_found" }, 404, corsHeaders(request));
      if (row.status !== "approved") return json({ error: "not_approved" }, 403, corsHeaders(request));

      return json({ ok: true, item: row }, 200, corsHeaders(request));
    }

    // JSONプレビュー用（DL数を増やさない）
    // GET /api/public/submissions/:id/json
    const publicJson = url.pathname.match(/^\/api\/public\/submissions\/([^\/]+)\/json$/);
    if (request.method === "GET" && publicJson) {
      const id = publicJson[1];
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT status, json_key, unit_id, submission_no FROM submissions WHERE id=? AND deleted_at IS NULL`
      ).bind(id).first();

      if (!row) return json({ error: "not_found" }, 404, corsHeaders(request));
      if (row.status !== "approved") return json({ error: "not_approved" }, 403, corsHeaders(request));

      const unitId = String(row.unit_id || ("unit_" + String(row.submission_no || id)));
      const rr = await readR2JsonTextAndRewrite(row.json_key, unitId);
      if (!rr.ok) return json({ error: rr.error }, 404, corsHeaders(request));

      return new Response(rr.text, {
        status: 200,
        headers: {
          ...corsHeaders(request),
          "Content-Type": "application/json; charset=utf-8",
        },
      });
    }

    // ダウンロード（approvedのみ）
    const dlMatch = url.pathname.match(/^\/api\/public\/submissions\/([^\/]+)\/download$/);
    if (request.method === "GET" && dlMatch) {
      const id = dlMatch[1];
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT status, json_key, title, unit_id, submission_no FROM submissions WHERE id=?`
      ).bind(id).first();

      if (!row) return json({ error: "not_found" }, 404, corsHeaders(request));
      if (row.status !== "approved") return json({ error: "not_approved" }, 403, corsHeaders(request));

      const obj = await env.UPLOADS_BUCKET.get(row.json_key);
      if (!obj) return json({ error: "file_missing" }, 404, corsHeaders(request));

      const unitId = String(row.unit_id || ("unit_" + String(row.submission_no || row.id)));
      const filename = safeFilename(unitId + ".json");

      // 返却時に id/unitId を必ず unitId に上書き（旧データ互換）
      const text = await obj.text();
      let bodyText = text;
      try {
        const j = JSON.parse(text);
        if (j && typeof j === "object") {
          rewriteUnitId(j, unitId);
          bodyText = JSON.stringify(j, null, 2);
        }
      } catch (_) {
        bodyText = text;
      }

      // DLカウント（失敗してもDL自体は返す）
      ctx.waitUntil(
        env.SUBMISSIONS_DB.prepare(`UPDATE submissions SET download_count = download_count + 1 WHERE id=?`)
          .bind(id)
          .run()
      );

      return new Response(bodyText, {
        status: 200,
        headers: {
          ...corsHeaders(request),
          "Content-Type": "application/json; charset=utf-8",
          "Content-Disposition": `attachment; filename="${filename}"`,
        },
      });
    }

    // =========================================================
    // MY (logged-in user)
    // =========================================================

    // 自分の投稿一覧
    // GET /api/my/submissions?scope=approved|all
    if (request.method === "GET" && url.pathname === "/api/my/submissions") {
      try {
        if (!env.SUBMISSIONS_DB) {
          return json({ ok: false, error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));
        }

        const auth = requireUser(request);
        if (!auth.ok) {
          return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));
        }

        const scope = String(url.searchParams.get("scope") || "").trim().toLowerCase();
        const approvedOnly = (scope === "approved");

        const sql = approvedOnly
          ? `SELECT
               id,
               submission_no,
               unit_id,
               title,
               description,
               tags,
               author_name,
               author_email,
               created_at,
               mod_version,
               download_count,
               thumb_mode,
               thumb_screen_id
             FROM submissions
             WHERE author_email=? AND status='approved' AND deleted_at IS NULL
             ORDER BY created_at DESC
             LIMIT 200`
          : `SELECT
               id,
               submission_no,
               unit_id,
               status,
               title,
               description,
               tags,
               author_name,
               author_email,
               created_at,
               mod_version,
               download_count,
               thumb_mode,
               thumb_screen_id
             FROM submissions
             WHERE author_email=? AND deleted_at IS NULL
             ORDER BY created_at DESC
             LIMIT 200`;

        const { results } = await env.SUBMISSIONS_DB.prepare(sql).bind(auth.email).all();
        return json({ ok: true, scope: approvedOnly ? "approved" : "all", items: results || [] }, 200, corsHeaders(request));
      } catch (e) {
        return json({ ok: false, error: "my_submissions_failed", message: String(e?.message || e) }, 500, corsHeaders(request));
      }
    }

    // =========================================================
    // ADMIN
    // =========================================================

    // 管理一覧（status / include_deleted / query）
    if (request.method === "GET" && url.pathname === "/api/admin/submissions") {
      const auth = requireAdmin(request);
      if (!auth.ok) {
        return json(
          {
            ok: false,
            error: "unauthorized",
            hint:
              "If you see 401: check the Cloudflare Access protected paths (mobcrafter.net/api/admin*), your admin Allow policy, and env.ADMIN_EMAILS.",
          },
          auth.status,
          corsHeaders(request)
        );
      }

      const status = (url.searchParams.get("status") || "pending").trim();
      const allowed = new Set(["pending", "approved", "rejected"]);
      const st = allowed.has(status) ? status : "pending";

      const includeDeleted = (url.searchParams.get("include_deleted") || "0").trim() === "1";
      const qraw = (url.searchParams.get("query") || "").trim().toLowerCase();
      const qlike = qraw ? `%${qraw}%` : null;

      let sql = `
        SELECT
          id,
          submission_no,
          unit_id,
          status,
          title,
          description,
          tags,
          author_name,
          author_email,
          created_at,
          updated_at,
          approved_at,
          approved_by,
          deleted_at,
          deleted_by,
          download_count,
          thumb_mode,
          thumb_screen_id
        FROM submissions
        WHERE status = ?
      `;

      const binds = [st];

      if (!includeDeleted) {
        sql += ` AND deleted_at IS NULL`;
      }

      if (qlike) {
        sql += `
          AND (
            LOWER(COALESCE(title,'')) LIKE ?
            OR LOWER(COALESCE(description,'')) LIKE ?
            OR LOWER(COALESCE(tags,'')) LIKE ?
            OR LOWER(COALESCE(author_name,'')) LIKE ?
            OR LOWER(COALESCE(author_email,'')) LIKE ?
            OR LOWER(COALESCE(unit_id,'')) LIKE ?
            OR LOWER(COALESCE(id,'')) LIKE ?
          )
        `;
        binds.push(qlike, qlike, qlike, qlike, qlike, qlike, qlike);
      }

      sql += ` ORDER BY created_at DESC LIMIT 300`;

      const stmt = env.SUBMISSIONS_DB.prepare(sql);
      const { results } = await stmt.bind(...binds).all();

      return json({ ok: true, items: results }, 200, corsHeaders(request));
    }

    // 承認
    const approveMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)\/approve$/);
    if (request.method === "POST" && approveMatch) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = approveMatch[1];
      const now = nowIso();

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET status='approved',
               approved_at=?,
               approved_by=?,
               updated_at=?
         WHERE id=?`
      ).bind(now, auth.email, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // 却下
    const rejectMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)\/reject$/);
    if (request.method === "POST" && rejectMatch) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = rejectMatch[1];
      const now = nowIso();

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET status='rejected',
               approved_at=NULL,
               approved_by=?,
               updated_at=?
         WHERE id=?`
      ).bind(auth.email, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // 削除（ソフトデリート：管理者）
    const delMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)$/);
    if (request.method === "DELETE" && delMatch) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = delMatch[1];
      const now = nowIso();

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id FROM submissions WHERE id=? AND deleted_at IS NULL`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET deleted_at=?,
               deleted_by=?,
               updated_at=?
         WHERE id=?`
      ).bind(now, auth.email, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // 復元（restore）
    const restoreMatch = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)\/restore$/);
    if (request.method === "POST" && restoreMatch) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = restoreMatch[1];
      const now = nowIso();

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET deleted_at=NULL,
               deleted_by=NULL,
               updated_at=?
         WHERE id=?`
      ).bind(now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // 管理者メタ更新：PUT /api/admin/submissions/:id
    const adminMeta = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)$/);
    if (request.method === "PUT" && adminMeta) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = adminMeta[1];

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      let body = null;
      try { body = await request.json(); } catch {}

      const title = body && body.title != null ? String(body.title).slice(0, 80) : null;
      const description = body && body.description != null ? String(body.description).slice(0, 2000) : null;

      let tagsText = null;
      if (body && body.tags != null) {
        if (Array.isArray(body.tags)) tagsText = body.tags.map((x) => String(x)).join(" ");
        else tagsText = String(body.tags);
      }

      const now = nowIso();
      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET title=COALESCE(?, title),
               description=COALESCE(?, description),
               tags=COALESCE(?, tags),
               updated_at=?
         WHERE id=?`
      ).bind(title, description, tagsText, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // 管理者JSON差し替え：PUT /api/admin/submissions/:id/json
    const adminJson = url.pathname.match(/^\/api\/admin\/submissions\/([^\/]+)\/json$/);
    if (request.method === "PUT" && adminJson) {
      const auth = requireAdmin(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = adminJson[1];

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id, unit_id, submission_no, json_key FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      let body = null;
      try { body = await request.json(); } catch {}

      const unitJson = body && body.json ? body.json : null;
      if (!unitJson || typeof unitJson !== "object") {
        return json({ ok: false, error: "invalid_json" }, 400, corsHeaders(request));
      }
      if (!Array.isArray(unitJson.blocks) || unitJson.blocks.length === 0) {
        return json({ ok: false, error: "blocks_required" }, 400, corsHeaders(request));
      }

      // unitId は固定（確定仕様）
      const unitId = String(row.unit_id || ("unit_" + String(row.submission_no || id)));
      rewriteUnitId(unitJson, unitId);

      const jsonKey = String(row.json_key || `submissions/${id}.json`);
      await env.UPLOADS_BUCKET.put(jsonKey, JSON.stringify(unitJson, null, 2), {
        httpMetadata: { contentType: "application/json; charset=utf-8" },
      });

      const now = nowIso();
      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions SET json_key=?, updated_at=? WHERE id=?`
      ).bind(jsonKey, now, id).run();

      return json({ ok: true, unit_id: unitId }, 200, corsHeaders(request));
    }

    // =========================================================
    // OWNER / ADMIN 共通（編集・差し替え・削除）
    // =========================================================

    // owner/admin: メタ取得
    // GET /api/submissions/:id
    const ownerMetaGet = url.pathname.match(/^\/api\/submissions\/([^\/]+)$/);
    if (request.method === "GET" && ownerMetaGet) {
      const auth = requireUser(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = ownerMetaGet[1];

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT
            id,
            submission_no,
            unit_id,
            status,
            title,
            description,
            tags,
            author_name,
            author_email,
            mc_version,
            mod_version,
            created_at,
            updated_at,
            download_count,
            thumb_mode,
            thumb_screen_id,
            deleted_at
         FROM submissions
         WHERE id=? LIMIT 1`
      ).bind(id).first();

      if (!row || row.deleted_at) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      if (!canOwnerOrAdmin(auth.email, row.author_email)) {
        return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
      }

      return json(row, 200, corsHeaders(request));
    }

    // JSON取得（owner/admin）
    // GET /api/submissions/:id/json
    const ownerJsonGet = url.pathname.match(/^\/api\/submissions\/([^\/]+)\/json$/);
    if (request.method === "GET" && ownerJsonGet) {
      const auth = requireUser(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = ownerJsonGet[1];

      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id, author_email, status, json_key, unit_id, submission_no, deleted_at
           FROM submissions
          WHERE id=? LIMIT 1`
      ).bind(id).first();

      if (!row || row.deleted_at) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      if (!canOwnerOrAdmin(auth.email, row.author_email)) {
        return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
      }

      const unitId = String(row.unit_id || ("unit_" + String(row.submission_no || id)));
      const rr = await readR2JsonTextAndRewrite(row.json_key, unitId);
      if (!rr.ok) return json({ ok: false, error: rr.error }, 404, corsHeaders(request));

      return new Response(rr.text, {
        status: 200,
        headers: {
          ...corsHeaders(request),
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "private, max-age=60",
        },
      });
    }

    // メタ更新：PUT /api/submissions/:id
    const ownerMeta = url.pathname.match(/^\/api\/submissions\/([^\/]+)$/);
    if (request.method === "PUT" && ownerMeta) {
      const auth = requireUser(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = ownerMeta[1];
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id, author_email, deleted_at FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row || row.deleted_at) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      if (!canOwnerOrAdmin(auth.email, row.author_email)) {
        return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
      }

      let body = null;
      try { body = await request.json(); } catch {}
      const title = body && body.title != null ? String(body.title).slice(0, 80) : null;
      const description = body && body.description != null ? String(body.description).slice(0, 2000) : null;

      let tagsText = null;
      if (body && body.tags != null) {
        if (Array.isArray(body.tags)) tagsText = body.tags.map((x) => String(x)).join(" ");
        else tagsText = String(body.tags);
      }

      const now = nowIso();
      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET title=COALESCE(?, title),
               description=COALESCE(?, description),
               tags=COALESCE(?, tags),
               updated_at=?
         WHERE id=?`
      ).bind(title, description, tagsText, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // JSON差し替え：PUT /api/submissions/:id/json
    const ownerJson = url.pathname.match(/^\/api\/submissions\/([^\/]+)\/json$/);
    if (request.method === "PUT" && ownerJson) {
      const auth = requireUser(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = ownerJson[1];
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id, author_email, unit_id, submission_no, json_key, deleted_at FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row || row.deleted_at) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      if (!canOwnerOrAdmin(auth.email, row.author_email)) {
        return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
      }

      let body = null;
      try { body = await request.json(); } catch {}
      const unitJson = body && body.json ? body.json : null;
      if (!unitJson || typeof unitJson !== "object") {
        return json({ ok: false, error: "invalid_json" }, 400, corsHeaders(request));
      }
      if (!Array.isArray(unitJson.blocks) || unitJson.blocks.length === 0) {
        return json({ ok: false, error: "blocks_required" }, 400, corsHeaders(request));
      }

      const unitId = String(row.unit_id || ("unit_" + String(row.submission_no || id)));
      rewriteUnitId(unitJson, unitId);

      const jsonKey = String(row.json_key || `submissions/${id}.json`);
      await env.UPLOADS_BUCKET.put(jsonKey, JSON.stringify(unitJson, null, 2), {
        httpMetadata: { contentType: "application/json; charset=utf-8" },
      });

      const now = nowIso();
      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions SET json_key=?, updated_at=? WHERE id=?`
      ).bind(jsonKey, now, id).run();

      return json({ ok: true, unit_id: unitId }, 200, corsHeaders(request));
    }

    // 削除（ソフトデリート：所有者 or 管理者）：DELETE /api/submissions/:id
    if (request.method === "DELETE" && ownerMeta) {
      const auth = requireUser(request);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));

      const id = ownerMeta[1];
      const row = await env.SUBMISSIONS_DB.prepare(
        `SELECT id, author_email, deleted_at FROM submissions WHERE id=? LIMIT 1`
      ).bind(id).first();
      if (!row || row.deleted_at) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

      if (!canOwnerOrAdmin(auth.email, row.author_email)) {
        return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
      }

      const now = nowIso();
      await env.SUBMISSIONS_DB.prepare(
        `UPDATE submissions
           SET deleted_at=?,
               deleted_by=?,
               updated_at=?
         WHERE id=?`
      ).bind(now, auth.email, now, id).run();

      return json({ ok: true }, 200, corsHeaders(request));
    }

    // =========================================================
    // SCREENSHOTS (submission_screens)
    // =========================================================

    const requireOwnerOrAdmin = async (req, submissionId) => {
      const u = requireUser(req);
      if (!u.ok) return { ok: false, status: u.status, email: u.email };
      const email = u.email;

      if (isAdminEmail(email)) return { ok: true, status: 200, email, isAdmin: true };

      const row = await env.SUBMISSIONS_DB
        .prepare(`SELECT id, author_email FROM submissions WHERE id=? AND deleted_at IS NULL`)
        .bind(submissionId)
        .first();

      if (!row) return { ok: false, status: 404, email };
      if ((row.author_email || "").toLowerCase() !== (email || "").toLowerCase()) {
        return { ok: false, status: 403, email };
      }
      return { ok: true, status: 200, email, isAdmin: false };
    };

    // Upload screenshot (owner/admin)
    // POST /api/submissions/:id/screens  (multipart/form-data: file)
    const uploadScreenMatch = url.pathname.match(/^\/api\/submissions\/([^\/]+)\/screens$/);
    if (request.method === "POST" && uploadScreenMatch) {
      try {
        if (!env.SUBMISSIONS_DB) return json({ ok: false, error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));
        if (!env.UPLOADS_BUCKET) return json({ ok: false, error: "missing_binding:UPLOADS_BUCKET" }, 500, corsHeaders(request));

        const submissionId = uploadScreenMatch[1];
        const auth = await requireOwnerOrAdmin(request, submissionId);
        if (!auth.ok) {
          const code = auth.status === 403 ? "forbidden" : auth.status === 404 ? "not_found" : "unauthorized";
          return json({ ok: false, error: code }, auth.status, corsHeaders(request));
        }

        const ct = request.headers.get("Content-Type") || "";
        if (!ct.toLowerCase().includes("multipart/form-data")) {
          return json({ ok: false, error: "content_type_must_be_multipart" }, 400, corsHeaders(request));
        }

        const form = await request.formData();
        const file = form.get("file");
        if (!file || typeof file === "string") {
          return json({ ok: false, error: "missing_file" }, 400, corsHeaders(request));
        }
        const thumbModeRaw = form.get("thumb_mode");
        const thumbMode = (String(thumbModeRaw || "3d").toLowerCase() === "screen") ? "screen" : "3d";

        const mime = (file.type || "").toLowerCase();
        if (!mime.startsWith("image/")) {
          return json({ ok: false, error: "invalid_mime", mime }, 400, corsHeaders(request));
        }

        // limit ~8MB
        if (file.size && file.size > 8 * 1024 * 1024) {
          return json({ ok: false, error: "file_too_large", size: file.size }, 400, corsHeaders(request));
        }

        const id = crypto.randomUUID();
        const ext = mime.includes("png") ? "png" : mime.includes("jpeg") || mime.includes("jpg") ? "jpg" : mime.includes("webp") ? "webp" : "img";
        const r2Key = `screens/${submissionId}/${id}.${ext}`;

        await env.UPLOADS_BUCKET.put(r2Key, file.stream(), {
          httpMetadata: { contentType: mime },
        });

        const now = nowIso();
        await env.SUBMISSIONS_DB.prepare(
          `INSERT INTO submission_screens (id, submission_id, r2_key, mime, w, h, created_at, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(id, submissionId, r2Key, mime, null, null, now, auth.email)
          .run();

        // ---- thumb update (if requested) ----
        try {
          const now2 = nowIso();
          if (thumbMode === "screen") {
            await env.SUBMISSIONS_DB.prepare(
              `UPDATE submissions
                 SET thumb_mode=?, thumb_screen_id=?, updated_at=?
               WHERE id=? AND deleted_at IS NULL`
            ).bind("screen", id, now2, submissionId).run();
          } else {
            await env.SUBMISSIONS_DB.prepare(
              `UPDATE submissions
                 SET thumb_mode=?, thumb_screen_id=NULL, updated_at=?
               WHERE id=? AND deleted_at IS NULL`
            ).bind("3d", now2, submissionId).run();
          }
        } catch (e) {
          // ここが失敗しても、画像アップロード自体は成功させる
        }

        return json({ ok: true, id, submission_id: submissionId, thumb_mode: thumbMode }, 200, corsHeaders(request));
      } catch (e) {
        return json({ ok: false, error: "screen_upload_failed", message: String(e?.message || e) }, 500, corsHeaders(request));
      }
    }

    // List screenshots (owner/admin)
    // GET /api/submissions/:id/screens
    const listPrivateScreensMatch = url.pathname.match(/^\/api\/submissions\/([^\/]+)\/screens$/);
    if (request.method === "GET" && listPrivateScreensMatch) {
      try {
        if (!env.SUBMISSIONS_DB) return json({ ok: false, error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));

        const submissionId = listPrivateScreensMatch[1];
        const auth = await requireOwnerOrAdmin(request, submissionId);
        if (!auth.ok) {
          const code = auth.status === 403 ? "forbidden" : auth.status === 404 ? "not_found" : "unauthorized";
          return json({ ok: false, error: code }, auth.status, corsHeaders(request));
        }

        const rows = await env.SUBMISSIONS_DB.prepare(
          `SELECT id, mime, created_at, created_by
             FROM submission_screens
            WHERE submission_id=?
            ORDER BY created_at DESC`
        ).bind(submissionId).all();

        return json({ ok: true, submission_id: submissionId, screens: rows.results || [] }, 200, corsHeaders(request));
      } catch (e) {
        return json({ ok: false, error: "screen_list_failed", message: String(e?.message || e) }, 500, corsHeaders(request));
      }
    }

    // List screenshots (public if approved OR owner/admin)
    // GET /api/public/submissions/:id/screens
    const listPublicScreensMatch = url.pathname.match(/^\/api\/public\/submissions\/([^\/]+)\/screens$/);
    if (request.method === "GET" && listPublicScreensMatch) {
      try {
        if (!env.SUBMISSIONS_DB) return json({ ok: false, error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));
        const submissionId = listPublicScreensMatch[1];

        const sub = await env.SUBMISSIONS_DB.prepare(
          `SELECT id, status, author_email FROM submissions WHERE id=? AND deleted_at IS NULL`
        ).bind(submissionId).first();

        if (!sub) return json({ ok: false, error: "not_found" }, 404, corsHeaders(request));

        const email = getAccessEmail(request);
        const isAdmin = email && isAdminEmail(email);
        const isOwner = email && (sub.author_email || "").toLowerCase() === email.toLowerCase();

        if (sub.status !== "approved" && !isAdmin && !isOwner) {
          return json({ ok: false, error: "forbidden" }, 403, corsHeaders(request));
        }

        const rows = await env.SUBMISSIONS_DB.prepare(
          `SELECT id, mime, created_at, created_by
             FROM submission_screens
            WHERE submission_id=?
            ORDER BY created_at DESC`
        ).bind(submissionId).all();

        return json({ ok: true, submission_id: submissionId, screens: rows.results || [] }, 200, corsHeaders(request));
      } catch (e) {
        return json({ ok: false, error: "screen_list_failed", message: String(e?.message || e) }, 500, corsHeaders(request));
      }
    }

    // Serve image bytes (owner/admin)
    // GET /api/screens/:screenId
    const getPrivateScreenMatch = url.pathname.match(/^\/api\/screens\/([^\/]+)$/);
    if (request.method === "GET" && getPrivateScreenMatch) {
      try {
        if (!env.SUBMISSIONS_DB) return new Response("missing SUBMISSIONS_DB", { status: 500, headers: corsHeaders(request) });
        if (!env.UPLOADS_BUCKET) return new Response("missing UPLOADS_BUCKET", { status: 500, headers: corsHeaders(request) });

        const screenId = getPrivateScreenMatch[1];
        const row = await env.SUBMISSIONS_DB.prepare(
          `SELECT s.id, s.submission_id, s.r2_key, s.mime, sub.author_email
             FROM submission_screens s
             JOIN submissions sub ON sub.id = s.submission_id
            WHERE s.id=? AND sub.deleted_at IS NULL`
        ).bind(screenId).first();

        if (!row) return new Response("not found", { status: 404, headers: corsHeaders(request) });

        const auth = await requireOwnerOrAdmin(request, row.submission_id);
        if (!auth.ok) {
          return new Response("forbidden", { status: auth.status, headers: corsHeaders(request) });
        }

        const obj = await env.UPLOADS_BUCKET.get(row.r2_key);
        if (!obj) return new Response("not found", { status: 404, headers: corsHeaders(request) });

        const headers = new Headers(corsHeaders(request));
        headers.set("Content-Type", row.mime || "application/octet-stream");
        headers.set("Cache-Control", "private, max-age=60");
        return new Response(obj.body, { status: 200, headers });
      } catch (e) {
        return new Response("error", { status: 500, headers: corsHeaders(request) });
      }
    }

    // Serve image bytes (public if approved OR owner/admin)
    // GET /api/public/screens/:screenId
    const getPublicScreenMatch = url.pathname.match(/^\/api\/public\/screens\/([^\/]+)$/);
    if (request.method === "GET" && getPublicScreenMatch) {
      try {
        if (!env.SUBMISSIONS_DB) return json({ ok: false, error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));
        if (!env.UPLOADS_BUCKET) return json({ ok: false, error: "missing_binding:UPLOADS_BUCKET" }, 500, corsHeaders(request));

        const screenId = getPublicScreenMatch[1];
        const row = await env.SUBMISSIONS_DB.prepare(
          `SELECT s.id, s.submission_id, s.r2_key, s.mime, sub.status, sub.author_email
             FROM submission_screens s
             JOIN submissions sub ON sub.id = s.submission_id
            WHERE s.id=? AND sub.deleted_at IS NULL`
        ).bind(screenId).first();

        if (!row) return new Response("not found", { status: 404, headers: corsHeaders(request) });

        const email = getAccessEmail(request);
        const isAdmin = email && isAdminEmail(email);
        const isOwner = email && (row.author_email || "").toLowerCase() === email.toLowerCase();
        if (row.status !== "approved" && !isAdmin && !isOwner) {
          return new Response("forbidden", { status: 403, headers: corsHeaders(request) });
        }

        const obj = await env.UPLOADS_BUCKET.get(row.r2_key);
        if (!obj) return new Response("not found", { status: 404, headers: corsHeaders(request) });

        const headers = new Headers(corsHeaders(request));
        headers.set("Content-Type", row.mime || "application/octet-stream");
        headers.set("Cache-Control", "public, max-age=300");
        return new Response(obj.body, { status: 200, headers });
      } catch (e) {
        return new Response("error", { status: 500, headers: corsHeaders(request) });
      }
    }

    // =========================================================
    // SUBMIT（既存のまま）
    // =========================================================
    if (request.method === "POST" && url.pathname === "/api/submit") {
      try {
        if (!env.SUBMISSIONS_DB) {
          return json({ error: "missing_binding:SUBMISSIONS_DB" }, 500, corsHeaders(request));
        }
        if (!env.UPLOADS_BUCKET) {
          return json({ error: "missing_binding:UPLOADS_BUCKET" }, 500, corsHeaders(request));
        }

        const auth = requireUser(request);
        if (!auth.ok) {
          return json({ ok: false, error: "unauthorized" }, auth.status, corsHeaders(request));
        }

        const body = await request.json();
        const unitJson = body && body.json ? body.json : body;

        if (!unitJson || typeof unitJson !== "object") {
          return json({ error: "invalid_json" }, 400, corsHeaders(request));
        }
        if (!Array.isArray(unitJson.blocks) || unitJson.blocks.length === 0) {
          return json({ error: "blocks_required" }, 400, corsHeaders(request));
        }

        const title = String(body.title || unitJson.title || "Untitled").slice(0, 80);
        const description = String(body.description || "").slice(0, 2000);
        const tags = Array.isArray(body.tags) ? body.tags.join(" ") : String(body.tags || "");

        const authorEmail = auth.email;
        const authorName = String(body.author_name || body.authorName || (authorEmail.split("@")[0] || "unknown")).slice(0, 60);

        const modVersion = body.mod_version ? String(body.mod_version).slice(0, 40) : null;
        const mcVersion = body.mc_version ? String(body.mc_version).slice(0, 40) : null;

        const now = nowIso();
        const id = crypto.randomUUID();

        await env.SUBMISSIONS_DB.prepare(
          `INSERT INTO submissions (id, status, title, description, tags, mc_version, mod_version, author_name, author_email, created_at, updated_at, download_count)
           VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
        ).bind(id, title, description, tags, mcVersion, modVersion, authorName, authorEmail, now, now).run();

        const row = await env.SUBMISSIONS_DB.prepare(
          `SELECT submission_no FROM submissions WHERE id=?`
        ).bind(id).first();

        const submissionNo = row && row.submission_no ? Number(row.submission_no) : 0;
        const unitId = "unit_" + String(submissionNo || id);

        rewriteUnitId(unitJson, unitId);

        const jsonKey = `submissions/${id}.json`;

        await env.UPLOADS_BUCKET.put(jsonKey, JSON.stringify(unitJson, null, 2), {
          httpMetadata: { contentType: "application/json; charset=utf-8" },
        });

        await env.SUBMISSIONS_DB.prepare(
          `UPDATE submissions SET json_key=?, unit_id=?, updated_at=? WHERE id=?`
        ).bind(jsonKey, unitId, now, id).run();

        return json({ ok: true, id, submission_no: submissionNo, unit_id: unitId }, 200, corsHeaders(request));
      } catch (e) {
        return json({ error: "submit_failed", message: String(e?.message || e) }, 500, corsHeaders(request));
      }
    }

    // Not found
    return json({ error: "not_found", path: url.pathname }, 404, corsHeaders(request));
  },
};
