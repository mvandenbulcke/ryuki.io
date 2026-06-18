-- 070_access_recertification.sql: align access_reviews to the engine vocabulary + persist campaigns.
ALTER TABLE access_reviews RENAME COLUMN target_type TO review_type;
ALTER TABLE access_reviews ALTER COLUMN status SET DEFAULT 'Pending';
UPDATE access_reviews SET status = 'Pending'    WHERE status IN ('Current','Overdue');
UPDATE access_reviews SET status = 'InProgress' WHERE status = 'UnderReview';
UPDATE access_reviews SET review_type = 'ADGroup'        WHERE review_type IN ('Role','Group');
UPDATE access_reviews SET review_type = 'SharePermission' WHERE review_type = 'FileShare';
-- Normalize review_history to a plain JSONB string array (engine access_details
-- is Vec<String>). Keep pre-existing string elements as-is; collapse legacy
-- {timestamp,action,reviewer,detail} objects to their `detail` string; skip
-- null/detail-less elements so the result is always an array of strings (never
-- [null], never a lost string array).
UPDATE access_reviews SET review_history = COALESCE(
    (SELECT jsonb_agg(
        CASE WHEN jsonb_typeof(elem) = 'string' THEN elem
             ELSE to_jsonb(elem->>'detail') END)
     FROM jsonb_array_elements(review_history) elem
     WHERE jsonb_typeof(elem) = 'string'
        OR (jsonb_typeof(elem) = 'object' AND elem->>'detail' IS NOT NULL)),
    '[]'::jsonb)
  WHERE jsonb_typeof(review_history) = 'array' AND jsonb_array_length(review_history) > 0;
ALTER TABLE access_reviews
    ADD CONSTRAINT chk_access_review_type   CHECK (review_type IN ('ADGroup','ServiceAccount','LocalAdmin','Sudo','SharePermission')),
    ADD CONSTRAINT chk_access_review_status CHECK (status IN ('Pending','InProgress','Approved','Revoked','Exempted'));
CREATE TABLE recertification_campaigns (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, start_date TIMESTAMPTZ NOT NULL, end_date TIMESTAMPTZ NOT NULL,
    review_type TEXT NOT NULL, reviewer_group TEXT NOT NULL,
    reviews_count INT NOT NULL DEFAULT 0, completed_count INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_campaign_review_type CHECK (review_type IN ('ADGroup','ServiceAccount','LocalAdmin','Sudo','SharePermission')),
    CONSTRAINT chk_campaign_status CHECK (status IN ('Active','Completed')));
INSERT INTO recertification_campaigns (id,name,start_date,end_date,review_type,reviewer_group,reviews_count,completed_count,status) VALUES
    ('arcamp-ad-q2','Q2 AD privileged access review', NOW()-INTERVAL '5 days', NOW()+INTERVAL '25 days','ADGroup','identity-governance',2,0,'Active'),
    -- No Sudo reviews are seeded by migration 030, so this campaign starts at 0/0
    -- (the create-campaign repo fn computes real counts from access_reviews).
    ('arcamp-sudo-q2','Q2 Linux sudo recertification', NOW()-INTERVAL '3 days', NOW()+INTERVAL '27 days','Sudo','linux-platform-reviewers',0,0,'Active');
