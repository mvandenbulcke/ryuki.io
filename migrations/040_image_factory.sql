CREATE TABLE golden_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name TEXT NOT NULL,
    os_family TEXT NOT NULL CHECK (os_family IN ('Windows', 'Linux')),
    os_version TEXT NOT NULL,
    distro TEXT NOT NULL,
    build_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'building' CHECK (status IN ('building', 'testing', 'promoted', 'superseded', 'failed')),
    supersedes_image_id UUID REFERENCES golden_images(id) ON DELETE SET NULL,
    site_scope TEXT NOT NULL,
    build_log TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (image_name, site_scope)
);

CREATE TABLE build_test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES golden_images(id) ON DELETE CASCADE,
    test_phase TEXT NOT NULL CHECK (test_phase IN ('security-scan', 'agent-checks', 'baseline-compliance')),
    passed BOOLEAN NOT NULL DEFAULT false,
    details TEXT NOT NULL DEFAULT '',
    run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_golden_images_site ON golden_images(site_scope);
CREATE INDEX idx_golden_images_status ON golden_images(site_scope, status);
CREATE INDEX idx_golden_images_os ON golden_images(os_family);
CREATE INDEX idx_golden_images_supersedes ON golden_images(supersedes_image_id);
CREATE INDEX idx_build_test_results_image ON build_test_results(image_id);

INSERT INTO golden_images (id, image_name, os_family, os_version, distro, build_date, status, supersedes_image_id, site_scope, build_log)
VALUES
    ('e0000400-4000-4000-4000-000000000001', 'win-svr-2022-defra-v1', 'Windows', '2022', 'Windows Server 2022 Datacenter', '2026-05-01 06:00:00+00', 'promoted', NULL, 'DEFRA', 'Build completed: 2026-05-01T06:00:00Z. Tests: security scan passed, agent checks passed, baseline compliance passed.'),
    ('e0000400-4000-4000-4000-000000000002', 'ubuntu-2404-defra-v1', 'Linux', '24.04', 'Ubuntu 24.04 LTS', '2026-05-02 06:00:00+00', 'promoted', NULL, 'DEFRA', 'Build completed: 2026-05-02T06:00:00Z. Tests: security scan passed, agent checks passed, baseline compliance passed.'),
    ('e0000400-4000-4000-4000-000000000003', 'win-svr-2025-gblon-v0', 'Windows', '2025', 'Windows Server 2025 Datacenter', '2026-06-10 08:00:00+00', 'building', NULL, 'GBLON', 'Build started: 2026-06-10T08:00:00Z. Status: OS installation completed, agent installation in progress.'),
    ('e0000400-4000-4000-4000-000000000004', 'win-svr-2019-defra-v0', 'Windows', '2019', 'Windows Server 2019 Datacenter', '2026-04-01 06:00:00+00', 'superseded', NULL, 'DEFRA', 'Superseded by img-001 (Windows Server 2022) on 2026-05-01. No further builds scheduled.');

INSERT INTO build_test_results (id, image_id, test_phase, passed, details, run_at)
VALUES
    ('t0000400-4000-4000-4000-000000000001', 'e0000400-4000-4000-4000-000000000001', 'security-scan', true, 'No critical or high CVEs found', '2026-05-01 04:00:00+00'),
    ('t0000400-4000-4000-4000-000000000002', 'e0000400-4000-4000-4000-000000000001', 'agent-checks', true, 'All monitoring agents operational', '2026-05-01 04:30:00+00'),
    ('t0000400-4000-4000-4000-000000000003', 'e0000400-4000-4000-4000-000000000001', 'baseline-compliance', true, 'CIS baseline compliant', '2026-05-01 05:00:00+00'),
    ('t0000400-4000-4000-4000-000000000004', 'e0000400-4000-4000-4000-000000000002', 'security-scan', true, 'No critical or high CVEs found', '2026-05-02 04:00:00+00'),
    ('t0000400-4000-4000-4000-000000000005', 'e0000400-4000-4000-4000-000000000002', 'agent-checks', true, 'All monitoring agents operational', '2026-05-02 04:30:00+00'),
    ('t0000400-4000-4000-4000-000000000006', 'e0000400-4000-4000-4000-000000000002', 'baseline-compliance', true, 'CIS baseline compliant', '2026-05-02 05:00:00+00');
