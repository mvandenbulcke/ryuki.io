-- 086_site_registry: durable storage for site active/inactive toggles.
-- Design: write-through cache — DB is the truth, the engine static is hydrated
-- at startup and updated on every toggle. Reads always go through the static.
CREATE TABLE IF NOT EXISTS site_registry (
    unlocode     TEXT        PRIMARY KEY,
    name         TEXT        NOT NULL,
    country      TEXT        NOT NULL,
    country_code TEXT        NOT NULL,
    timezone     TEXT        NOT NULL,
    active       BOOLEAN     NOT NULL DEFAULT true
);

INSERT INTO site_registry (unlocode, name, country, country_code, timezone, active) VALUES
-- Germany
('DEBER', 'Berlin', 'Germany', 'DE', 'Europe/Berlin', true),
('DEFRA', 'Frankfurt', 'Germany', 'DE', 'Europe/Berlin', true),
('DEMUC', 'München', 'Germany', 'DE', 'Europe/Berlin', false),
('DEHAM', 'Hamburg', 'Germany', 'DE', 'Europe/Berlin', false),
('DEDUS', 'Düsseldorf', 'Germany', 'DE', 'Europe/Berlin', false),
-- France
('FRPAR', 'Paris', 'France', 'FR', 'Europe/Paris', true),
('FRMRS', 'Marseille', 'France', 'FR', 'Europe/Paris', false),
('FRLYS', 'Lyon', 'France', 'FR', 'Europe/Paris', false),
('FRNCE', 'Nice', 'France', 'FR', 'Europe/Paris', false),
-- United Kingdom
('GBLON', 'London', 'United Kingdom', 'GB', 'Europe/London', true),
('GBMAN', 'Manchester', 'United Kingdom', 'GB', 'Europe/London', false),
('GBBIR', 'Birmingham', 'United Kingdom', 'GB', 'Europe/London', false),
('GBEDB', 'Edinburgh', 'United Kingdom', 'GB', 'Europe/London', false),
-- Netherlands
('NLAMS', 'Amsterdam', 'Netherlands', 'NL', 'Europe/Amsterdam', true),
('NLRTM', 'Rotterdam', 'Netherlands', 'NL', 'Europe/Amsterdam', false),
('NLEIN', 'Eindhoven', 'Netherlands', 'NL', 'Europe/Amsterdam', false),
-- Spain
('ESMAD', 'Madrid', 'Spain', 'ES', 'Europe/Madrid', false),
('ESBCN', 'Barcelona', 'Spain', 'ES', 'Europe/Madrid', false),
-- Italy
('ITMIL', 'Milano', 'Italy', 'IT', 'Europe/Rome', false),
('ITROM', 'Roma', 'Italy', 'IT', 'Europe/Rome', false),
-- Switzerland
('CHZRH', 'Zürich', 'Switzerland', 'CH', 'Europe/Zurich', false),
('CHGVA', 'Genève', 'Switzerland', 'CH', 'Europe/Zurich', false),
-- Austria
('ATVIE', 'Wien', 'Austria', 'AT', 'Europe/Vienna', false),
-- Belgium
('BEANR', 'Antwerpen', 'Belgium', 'BE', 'Europe/Brussels', false),
('BEBRU', 'Brussels', 'Belgium', 'BE', 'Europe/Brussels', false),
-- Sweden (UN/LOCODE with space)
('SE STO', 'Stockholm', 'Sweden', 'SE', 'Europe/Stockholm', false),
('SE GOT', 'Göteborg', 'Sweden', 'SE', 'Europe/Stockholm', false),
-- Denmark
('DKCPH', 'København', 'Denmark', 'DK', 'Europe/Copenhagen', false),
-- Norway
('NOOSL', 'Oslo', 'Norway', 'NO', 'Europe/Oslo', false),
-- Finland
('FI HEL', 'Helsinki', 'Finland', 'FI', 'Europe/Helsinki', false),
-- Ireland
('IE DUB', 'Dublin', 'Ireland', 'IE', 'Europe/Dublin', false),
-- Portugal
('PT LIS', 'Lisboa', 'Portugal', 'PT', 'Europe/Lisbon', false),
-- Poland
('PL WAW', 'Warszawa', 'Poland', 'PL', 'Europe/Warsaw', false),
-- Czech Republic
('CZPRG', 'Praha', 'Czech Republic', 'CZ', 'Europe/Prague', false),
-- Hungary
('HU BUD', 'Budapest', 'Hungary', 'HU', 'Europe/Budapest', false),
-- Romania
('RO BUH', 'Bucuresti', 'Romania', 'RO', 'Europe/Bucharest', false),
-- Greece
('GR ATH', 'Athina', 'Greece', 'GR', 'Europe/Athens', false),
-- Bulgaria
('BG SOF', 'Sofia', 'Bulgaria', 'BG', 'Europe/Sofia', false),
-- Croatia
('HR ZAG', 'Zagreb', 'Croatia', 'HR', 'Europe/Zagreb', false),
-- Slovakia
('SK BTS', 'Bratislava', 'Slovakia', 'SK', 'Europe/Bratislava', false),
-- Slovenia
('SI LJU', 'Ljubljana', 'Slovenia', 'SI', 'Europe/Ljubljana', false),
-- Estonia
('EE TLL', 'Tallinn', 'Estonia', 'EE', 'Europe/Tallinn', false),
-- Latvia
('LV RIX', 'Riga', 'Latvia', 'LV', 'Europe/Riga', false),
-- Lithuania
('LT VNO', 'Vilnius', 'Lithuania', 'LT', 'Europe/Vilnius', false),
-- Iceland
('IS REY', 'Reykjavik', 'Iceland', 'IS', 'Atlantic/Reykjavik', false),
-- United States
('USNYC', 'New York', 'United States', 'US', 'America/New_York', false),
('USASH', 'Ashburn', 'United States', 'US', 'America/New_York', false),
('USCHI', 'Chicago', 'United States', 'US', 'America/Chicago', false),
('USDAL', 'Dallas', 'United States', 'US', 'America/Chicago', false),
('USLAX', 'Los Angeles', 'United States', 'US', 'America/Los_Angeles', false),
('USSFO', 'San Francisco', 'United States', 'US', 'America/Los_Angeles', false),
('USSEA', 'Seattle', 'United States', 'US', 'America/Los_Angeles', false),
('USPHX', 'Phoenix', 'United States', 'US', 'America/Phoenix', false),
('USDEN', 'Denver', 'United States', 'US', 'America/Denver', false),
('USMIA', 'Miami', 'United States', 'US', 'America/New_York', false),
('USATL', 'Atlanta', 'United States', 'US', 'America/New_York', false),
-- Canada
('CA TOR', 'Toronto', 'Canada', 'CA', 'America/Toronto', false),
('CA VAN', 'Vancouver', 'Canada', 'CA', 'America/Vancouver', false),
('CA MTR', 'Montréal', 'Canada', 'CA', 'America/Toronto', false),
-- Japan
('JP TYO', 'Tokyo', 'Japan', 'JP', 'Asia/Tokyo', false),
('JP OSA', 'Osaka', 'Japan', 'JP', 'Asia/Tokyo', false),
-- South Korea
('KR SEL', 'Seoul', 'South Korea', 'KR', 'Asia/Seoul', false),
('KR PUS', 'Busan', 'South Korea', 'KR', 'Asia/Seoul', false),
-- Singapore
('SGSIN', 'Singapore', 'Singapore', 'SG', 'Asia/Singapore', false),
-- Hong Kong
('HK HKG', 'Hong Kong', 'Hong Kong', 'HK', 'Asia/Hong_Kong', false),
-- Taiwan
('TW TPE', 'Taipei', 'Taiwan', 'TW', 'Asia/Taipei', false),
-- China
('CN SHA', 'Shanghai', 'China', 'CN', 'Asia/Shanghai', false),
('CN BJS', 'Beijing', 'China', 'CN', 'Asia/Shanghai', false),
-- India
('IN BOM', 'Mumbai', 'India', 'IN', 'Asia/Kolkata', false),
('IN DEL', 'Delhi', 'India', 'IN', 'Asia/Kolkata', false),
('IN BLR', 'Bangalore', 'India', 'IN', 'Asia/Kolkata', false),
('IN HYD', 'Hyderabad', 'India', 'IN', 'Asia/Kolkata', false),
-- Australia
('AU SYD', 'Sydney', 'Australia', 'AU', 'Australia/Sydney', false),
('AU MEL', 'Melbourne', 'Australia', 'AU', 'Australia/Melbourne', false),
-- New Zealand
('NZ AKL', 'Auckland', 'New Zealand', 'NZ', 'Pacific/Auckland', false),
-- United Arab Emirates
('AE DXB', 'Dubai', 'United Arab Emirates', 'AE', 'Asia/Dubai', false),
('AE AUH', 'Abu Dhabi', 'United Arab Emirates', 'AE', 'Asia/Dubai', false),
-- Saudi Arabia
('SA RUH', 'Riyadh', 'Saudi Arabia', 'SA', 'Asia/Riyadh', false),
-- Qatar
('QA DOH', 'Doha', 'Qatar', 'QA', 'Asia/Qatar', false),
-- Israel
('IL TLV', 'Tel Aviv', 'Israel', 'IL', 'Asia/Jerusalem', false),
-- Brazil
('BR SAO', 'São Paulo', 'Brazil', 'BR', 'America/Sao_Paulo', false),
('BR RIO', 'Rio de Janeiro', 'Brazil', 'BR', 'America/Sao_Paulo', false),
-- Argentina
('AR BUE', 'Buenos Aires', 'Argentina', 'AR', 'America/Argentina/Buenos_Aires', false),
-- Chile
('CL SCL', 'Santiago', 'Chile', 'CL', 'America/Santiago', false),
-- South Africa
('ZA JNB', 'Johannesburg', 'South Africa', 'ZA', 'Africa/Johannesburg', false),
('ZA CPT', 'Cape Town', 'South Africa', 'ZA', 'Africa/Johannesburg', false),
-- Kenya
('KE NBO', 'Nairobi', 'Kenya', 'KE', 'Africa/Nairobi', false),
-- Nigeria
('NG LOS', 'Lagos', 'Nigeria', 'NG', 'Africa/Lagos', false)
ON CONFLICT (unlocode) DO NOTHING;
