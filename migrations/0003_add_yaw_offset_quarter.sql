-- Add per-unit thumbnail yaw to submissions
ALTER TABLE submissions ADD COLUMN yaw_offset_quarter INTEGER;

-- Dodo (frontYaw=0): canonical view = drawIso 0° = quarter 0
UPDATE submissions SET yaw_offset_quarter = 0 WHERE id = '8e7f1bc4-4748-48cc-8c91-2c63e07d2750';

-- BlueEyesWhiteDragon (frontYaw=0): canonical view = drawIso 0° = quarter 0
UPDATE submissions SET yaw_offset_quarter = 0 WHERE id = 'db3c84ad-2790-4a2f-a618-8c6f3f36dd05';

-- ShadowBeast (frontYaw=90): canonical view = drawIso 270° = quarter 3
-- (same as default 270°, so leaving NULL is equivalent, but set explicitly for clarity)
UPDATE submissions SET yaw_offset_quarter = 3 WHERE id = '3004c1da-b570-48f1-8b87-df29c8d0a3bc';

-- Moblin, Jamirus: frontYaw unknown/NULL → leave NULL (use default 270°)
