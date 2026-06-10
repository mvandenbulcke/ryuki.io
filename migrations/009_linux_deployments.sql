CREATE TABLE linux_deployment_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    distro TEXT NOT NULL,
    version TEXT NOT NULL,
    site TEXT NOT NULL,
    cpu INTEGER NOT NULL DEFAULT 0,
    memory_gb INTEGER NOT NULL DEFAULT 0,
    disk_gb INTEGER NOT NULL DEFAULT 0,
    hostname TEXT NOT NULL,
    network TEXT NOT NULL DEFAULT '',
    hardening_profile TEXT NOT NULL DEFAULT 'cis-level-1',
    status TEXT NOT NULL DEFAULT 'draft',
    plan JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE linux_distro_catalog (
    distro TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    package_manager TEXT NOT NULL,
    default_network TEXT NOT NULL,
    firewall TEXT NOT NULL,
    min_version TEXT NOT NULL,
    max_version TEXT NOT NULL,
    supported_versions JSONB NOT NULL DEFAULT '[]',
    category TEXT NOT NULL DEFAULT 'community'
);

INSERT INTO linux_distro_catalog (distro, display_name, package_manager, default_network, firewall, min_version, max_version, supported_versions, category) VALUES
    ('sles', 'SUSE Linux Enterprise Server', 'zypper', 'wicked', 'firewalld', '15.0', '15.6', '["15.4","15.5","15.6"]', 'enterprise'),
    ('rhel', 'Red Hat Enterprise Linux', 'dnf', 'NetworkManager', 'firewalld', '8.0', '9.5', '["8.8","8.10","9.4","9.5"]', 'enterprise'),
    ('rocky', 'Rocky Linux', 'dnf', 'NetworkManager', 'firewalld', '8.0', '9.5', '["8.10","9.4","9.5"]', 'enterprise'),
    ('alma', 'AlmaLinux', 'dnf', 'NetworkManager', 'firewalld', '8.0', '9.5', '["8.10","9.4","9.5"]', 'enterprise'),
    ('ubuntu', 'Ubuntu Server', 'apt', 'netplan', 'ufw', '20.04', '24.04', '["20.04 LTS","22.04 LTS","24.04 LTS"]', 'community'),
    ('debian', 'Debian', 'apt', 'ifupdown', 'nftables', '11', '12', '["11 (bullseye)","12 (bookworm)"]', 'community');
