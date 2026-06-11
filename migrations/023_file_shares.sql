CREATE TABLE file_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    unc_path TEXT NOT NULL,
    server_name TEXT NOT NULL,
    site TEXT NOT NULL,
    size_gb NUMERIC(12, 2) NOT NULL,
    owner TEXT NOT NULL,
    last_recertification TIMESTAMPTZ NOT NULL,
    recertification_due TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'NeedsRecertification'
);

CREATE TABLE ntfs_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_share_id UUID NOT NULL REFERENCES file_shares(id),
    folder_path TEXT NOT NULL,
    permission_type TEXT NOT NULL,
    ad_group TEXT NOT NULL,
    principal TEXT NOT NULL,
    inherited BOOLEAN NOT NULL DEFAULT false,
    last_reviewed TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_file_shares_site ON file_shares(site);
CREATE INDEX idx_file_shares_status ON file_shares(status);
CREATE INDEX idx_ntfs_permissions_share ON ntfs_permissions(file_share_id);

INSERT INTO file_shares (unc_path, server_name, site, size_gb, owner, last_recertification, recertification_due, status) VALUES
    ('\\fs01\Finance', 'fs01.example.local', 'DEFRA', 512.0, 'alice.williams', NOW() - INTERVAL '200 days', NOW() + INTERVAL '180 days', 'Compliant'),
    ('\\fs02\Engineering', 'fs02.example.local', 'GBLON', 1024.0, 'bob.johnson', NOW() - INTERVAL '400 days', NOW() - INTERVAL '30 days', 'Overdue'),
    ('\\fs03\HR', 'fs03.example.local', 'DEFRA', 256.0, 'carol.smith', NOW() - INTERVAL '400 days', NOW() - INTERVAL '5 days', 'NeedsRecertification');

INSERT INTO ntfs_permissions (file_share_id, folder_path, permission_type, ad_group, principal, inherited, last_reviewed)
SELECT id, '\Finance\Reports', 'Modify', 'GG-Finance-RW', 'GG-Finance-RW@example.local', false, NOW()
FROM file_shares WHERE unc_path = '\\fs01\Finance'
UNION ALL
SELECT id, '\Finance\Payroll', 'FullControl', 'GG-Finance-Admins', 'GG-Finance-Admins@example.local', false, NOW()
FROM file_shares WHERE unc_path = '\\fs01\Finance'
UNION ALL
SELECT id, '\Finance\Public', 'Read', 'Everyone', 'Everyone', true, NOW()
FROM file_shares WHERE unc_path = '\\fs01\Finance'
UNION ALL
SELECT id, '\Engineering\Source', 'Modify', 'GG-Engineering-Dev', 'GG-Engineering-Dev@example.local', false, NOW() - INTERVAL '400 days'
FROM file_shares WHERE unc_path = '\\fs02\Engineering'
UNION ALL
SELECT id, '\Engineering\Design', 'FullControl', 'Domain Users', 'Domain Users@example.local', true, NOW() - INTERVAL '400 days'
FROM file_shares WHERE unc_path = '\\fs02\Engineering'
UNION ALL
SELECT id, '\HR\EmployeeRecords', 'Read', 'GG-HR-Staff', 'GG-HR-Staff@example.local', false, NOW()
FROM file_shares WHERE unc_path = '\\fs03\HR';
