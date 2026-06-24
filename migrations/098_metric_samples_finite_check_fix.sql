-- 098_metric_samples_finite_check_fix.sql — correct the finite CHECK on
-- metric_samples (#34 follow-up).
--
-- Migration 096 added `CHECK (value = value AND value <> 'Infinity' AND value
-- <> '-Infinity')` intending to reject non-finite values. That is INEFFECTIVE
-- against NaN in PostgreSQL: Postgres deliberately treats `NaN = NaN` as TRUE
-- (so NaN can sort and index), so `value = value` is true even for NaN and the
-- constraint never rejected it. (The API already rejects non-finite samples, so
-- this was a defense-in-depth gap, not an exploitable hole.)
--
-- The correct finite test is a range check: a finite value is strictly between
-- -Infinity and +Infinity. NaN fails `< 'Infinity'` (Postgres ranks NaN above
-- every non-NaN value, so it is not < +Inf), and ±Inf fail their own bounds.

ALTER TABLE metric_samples
    DROP CONSTRAINT IF EXISTS metric_samples_value_finite;

ALTER TABLE metric_samples
    ADD CONSTRAINT metric_samples_value_finite
        CHECK (value > '-Infinity'::float8 AND value < 'Infinity'::float8);
