use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Mutex;

pub const SITE_CODE_MAX_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteEntry {
    /// Canonical site code. The legacy field name is retained for API and
    /// persistence compatibility; custom site codes are stored here as well.
    pub unlocode: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub timezone: String,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SiteCodeSystem {
    Unlocode,
    Custom,
}

impl SiteCodeSystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unlocode => "unlocode",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone)]
struct RegisteredSite {
    site: SiteEntry,
    code_system: SiteCodeSystem,
}

/// Return the canonical identifier used for storage, scoping and comparison.
///
/// UN/LOCODE inputs accept the published `CC LLL` display form but are stored
/// compact (`CCLLL`). Custom identifiers use 2-32 ASCII letters, digits, dots,
/// underscores or hyphens, must start/end with an alphanumeric character, and
/// are upper-cased. This excludes URL/path delimiters and case aliases.
pub fn normalize_site_code(input: &str, code_system: SiteCodeSystem) -> Result<String, String> {
    let upper = input.trim().to_ascii_uppercase();
    let code = match code_system {
        SiteCodeSystem::Unlocode => {
            let compact = if upper.len() == 6 && upper.as_bytes().get(2) == Some(&b' ') {
                format!("{}{}", &upper[..2], &upper[3..])
            } else {
                upper
            };
            let bytes = compact.as_bytes();
            if bytes.len() != 5
                || !bytes[..2].iter().all(u8::is_ascii_alphabetic)
                || !bytes[2..].iter().all(u8::is_ascii_alphanumeric)
            {
                return Err(
                    "UN/LOCODE must contain a two-letter country code and three alphanumeric location characters"
                        .into(),
                );
            }
            compact
        }
        SiteCodeSystem::Custom => {
            let bytes = upper.as_bytes();
            if !(2..=SITE_CODE_MAX_LEN).contains(&bytes.len()) {
                return Err(format!(
                    "custom site code must be 2-{SITE_CODE_MAX_LEN} ASCII characters"
                ));
            }
            if !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            {
                return Err(
                    "custom site code must start and end with a letter or digit and contain only ASCII letters, digits, '.', '_' or '-'"
                        .into(),
                );
            }
            upper
        }
    };
    Ok(code)
}

/// Normalize an identifier whose registered code system is not yet known.
/// Compact/display-form UN/LOCODEs and custom codes share one canonical lookup
/// namespace, so a code cannot resolve to two different sites.
pub fn normalize_site_code_for_lookup(input: &str) -> Result<String, String> {
    normalize_site_code(input, SiteCodeSystem::Unlocode)
        .or_else(|_| normalize_site_code(input, SiteCodeSystem::Custom))
}

// ─── UN/LOCODE reference data (ISO 3166-1 alpha-2 country codes) ───
// Covers major datacenter locations globally.
// Format: UN/LOCODE = 2-char country code + 3-char location code.

fn reference_sites() -> Vec<SiteEntry> {
    vec![
        // ── Germany (DE) ──
        SiteEntry {
            unlocode: "DEBER".into(),
            name: "Berlin".into(),
            country: "Germany".into(),
            country_code: "DE".into(),
            timezone: "Europe/Berlin".into(),
            active: true,
        },
        SiteEntry {
            unlocode: "DEFRA".into(),
            name: "Frankfurt".into(),
            country: "Germany".into(),
            country_code: "DE".into(),
            timezone: "Europe/Berlin".into(),
            active: true,
        },
        SiteEntry {
            unlocode: "DEMUC".into(),
            name: "München".into(),
            country: "Germany".into(),
            country_code: "DE".into(),
            timezone: "Europe/Berlin".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "DEHAM".into(),
            name: "Hamburg".into(),
            country: "Germany".into(),
            country_code: "DE".into(),
            timezone: "Europe/Berlin".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "DEDUS".into(),
            name: "Düsseldorf".into(),
            country: "Germany".into(),
            country_code: "DE".into(),
            timezone: "Europe/Berlin".into(),
            active: false,
        },
        // ── France (FR) ──
        SiteEntry {
            unlocode: "FRPAR".into(),
            name: "Paris".into(),
            country: "France".into(),
            country_code: "FR".into(),
            timezone: "Europe/Paris".into(),
            active: true,
        },
        SiteEntry {
            unlocode: "FRMRS".into(),
            name: "Marseille".into(),
            country: "France".into(),
            country_code: "FR".into(),
            timezone: "Europe/Paris".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "FRLYS".into(),
            name: "Lyon".into(),
            country: "France".into(),
            country_code: "FR".into(),
            timezone: "Europe/Paris".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "FRNCE".into(),
            name: "Nice".into(),
            country: "France".into(),
            country_code: "FR".into(),
            timezone: "Europe/Paris".into(),
            active: false,
        },
        // ── United Kingdom (GB) ──
        SiteEntry {
            unlocode: "GBLON".into(),
            name: "London".into(),
            country: "United Kingdom".into(),
            country_code: "GB".into(),
            timezone: "Europe/London".into(),
            active: true,
        },
        SiteEntry {
            unlocode: "GBMAN".into(),
            name: "Manchester".into(),
            country: "United Kingdom".into(),
            country_code: "GB".into(),
            timezone: "Europe/London".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "GBBIR".into(),
            name: "Birmingham".into(),
            country: "United Kingdom".into(),
            country_code: "GB".into(),
            timezone: "Europe/London".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "GBEDB".into(),
            name: "Edinburgh".into(),
            country: "United Kingdom".into(),
            country_code: "GB".into(),
            timezone: "Europe/London".into(),
            active: false,
        },
        // ── Netherlands (NL) ──
        SiteEntry {
            unlocode: "NLAMS".into(),
            name: "Amsterdam".into(),
            country: "Netherlands".into(),
            country_code: "NL".into(),
            timezone: "Europe/Amsterdam".into(),
            active: true,
        },
        SiteEntry {
            unlocode: "NLRTM".into(),
            name: "Rotterdam".into(),
            country: "Netherlands".into(),
            country_code: "NL".into(),
            timezone: "Europe/Amsterdam".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "NLEIN".into(),
            name: "Eindhoven".into(),
            country: "Netherlands".into(),
            country_code: "NL".into(),
            timezone: "Europe/Amsterdam".into(),
            active: false,
        },
        // ── Spain (ES) ──
        SiteEntry {
            unlocode: "ESMAD".into(),
            name: "Madrid".into(),
            country: "Spain".into(),
            country_code: "ES".into(),
            timezone: "Europe/Madrid".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "ESBCN".into(),
            name: "Barcelona".into(),
            country: "Spain".into(),
            country_code: "ES".into(),
            timezone: "Europe/Madrid".into(),
            active: false,
        },
        // ── Italy (IT) ──
        SiteEntry {
            unlocode: "ITMIL".into(),
            name: "Milano".into(),
            country: "Italy".into(),
            country_code: "IT".into(),
            timezone: "Europe/Rome".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "ITROM".into(),
            name: "Roma".into(),
            country: "Italy".into(),
            country_code: "IT".into(),
            timezone: "Europe/Rome".into(),
            active: false,
        },
        // ── Switzerland (CH) ──
        SiteEntry {
            unlocode: "CHZRH".into(),
            name: "Zürich".into(),
            country: "Switzerland".into(),
            country_code: "CH".into(),
            timezone: "Europe/Zurich".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "CHGVA".into(),
            name: "Genève".into(),
            country: "Switzerland".into(),
            country_code: "CH".into(),
            timezone: "Europe/Zurich".into(),
            active: false,
        },
        // ── Austria (AT) ──
        SiteEntry {
            unlocode: "ATVIE".into(),
            name: "Wien".into(),
            country: "Austria".into(),
            country_code: "AT".into(),
            timezone: "Europe/Vienna".into(),
            active: false,
        },
        // ── Belgium (BE) ──
        SiteEntry {
            unlocode: "BEANR".into(),
            name: "Antwerpen".into(),
            country: "Belgium".into(),
            country_code: "BE".into(),
            timezone: "Europe/Brussels".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "BEBRU".into(),
            name: "Brussels".into(),
            country: "Belgium".into(),
            country_code: "BE".into(),
            timezone: "Europe/Brussels".into(),
            active: false,
        },
        // ── Sweden (SE) ──
        SiteEntry {
            unlocode: "SE STO".into(),
            name: "Stockholm".into(),
            country: "Sweden".into(),
            country_code: "SE".into(),
            timezone: "Europe/Stockholm".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "SE GOT".into(),
            name: "Göteborg".into(),
            country: "Sweden".into(),
            country_code: "SE".into(),
            timezone: "Europe/Stockholm".into(),
            active: false,
        },
        // ── Denmark (DK) ──
        SiteEntry {
            unlocode: "DKCPH".into(),
            name: "København".into(),
            country: "Denmark".into(),
            country_code: "DK".into(),
            timezone: "Europe/Copenhagen".into(),
            active: false,
        },
        // ── Norway (NO) ──
        SiteEntry {
            unlocode: "NOOSL".into(),
            name: "Oslo".into(),
            country: "Norway".into(),
            country_code: "NO".into(),
            timezone: "Europe/Oslo".into(),
            active: false,
        },
        // ── Finland (FI) ──
        SiteEntry {
            unlocode: "FI HEL".into(),
            name: "Helsinki".into(),
            country: "Finland".into(),
            country_code: "FI".into(),
            timezone: "Europe/Helsinki".into(),
            active: false,
        },
        // ── Ireland (IE) ──
        SiteEntry {
            unlocode: "IE DUB".into(),
            name: "Dublin".into(),
            country: "Ireland".into(),
            country_code: "IE".into(),
            timezone: "Europe/Dublin".into(),
            active: false,
        },
        // ── Portugal (PT) ──
        SiteEntry {
            unlocode: "PT LIS".into(),
            name: "Lisboa".into(),
            country: "Portugal".into(),
            country_code: "PT".into(),
            timezone: "Europe/Lisbon".into(),
            active: false,
        },
        // ── Poland (PL) ──
        SiteEntry {
            unlocode: "PL WAW".into(),
            name: "Warszawa".into(),
            country: "Poland".into(),
            country_code: "PL".into(),
            timezone: "Europe/Warsaw".into(),
            active: false,
        },
        // ── Czech Republic (CZ) ──
        SiteEntry {
            unlocode: "CZPRG".into(),
            name: "Praha".into(),
            country: "Czech Republic".into(),
            country_code: "CZ".into(),
            timezone: "Europe/Prague".into(),
            active: false,
        },
        // ── Hungary (HU) ──
        SiteEntry {
            unlocode: "HU BUD".into(),
            name: "Budapest".into(),
            country: "Hungary".into(),
            country_code: "HU".into(),
            timezone: "Europe/Budapest".into(),
            active: false,
        },
        // ── Romania (RO) ──
        SiteEntry {
            unlocode: "RO BUH".into(),
            name: "Bucuresti".into(),
            country: "Romania".into(),
            country_code: "RO".into(),
            timezone: "Europe/Bucharest".into(),
            active: false,
        },
        // ── Greece (GR) ──
        SiteEntry {
            unlocode: "GR ATH".into(),
            name: "Athina".into(),
            country: "Greece".into(),
            country_code: "GR".into(),
            timezone: "Europe/Athens".into(),
            active: false,
        },
        // ── Bulgaria (BG) ──
        SiteEntry {
            unlocode: "BG SOF".into(),
            name: "Sofia".into(),
            country: "Bulgaria".into(),
            country_code: "BG".into(),
            timezone: "Europe/Sofia".into(),
            active: false,
        },
        // ── Croatia (HR) ──
        SiteEntry {
            unlocode: "HR ZAG".into(),
            name: "Zagreb".into(),
            country: "Croatia".into(),
            country_code: "HR".into(),
            timezone: "Europe/Zagreb".into(),
            active: false,
        },
        // ── Slovakia (SK) ──
        SiteEntry {
            unlocode: "SK BTS".into(),
            name: "Bratislava".into(),
            country: "Slovakia".into(),
            country_code: "SK".into(),
            timezone: "Europe/Bratislava".into(),
            active: false,
        },
        // ── Slovenia (SI) ──
        SiteEntry {
            unlocode: "SI LJU".into(),
            name: "Ljubljana".into(),
            country: "Slovenia".into(),
            country_code: "SI".into(),
            timezone: "Europe/Ljubljana".into(),
            active: false,
        },
        // ── Estonia (EE) ──
        SiteEntry {
            unlocode: "EE TLL".into(),
            name: "Tallinn".into(),
            country: "Estonia".into(),
            country_code: "EE".into(),
            timezone: "Europe/Tallinn".into(),
            active: false,
        },
        // ── Latvia (LV) ──
        SiteEntry {
            unlocode: "LV RIX".into(),
            name: "Riga".into(),
            country: "Latvia".into(),
            country_code: "LV".into(),
            timezone: "Europe/Riga".into(),
            active: false,
        },
        // ── Lithuania (LT) ──
        SiteEntry {
            unlocode: "LT VNO".into(),
            name: "Vilnius".into(),
            country: "Lithuania".into(),
            country_code: "LT".into(),
            timezone: "Europe/Vilnius".into(),
            active: false,
        },
        // ── Iceland (IS) ──
        SiteEntry {
            unlocode: "IS REY".into(),
            name: "Reykjavik".into(),
            country: "Iceland".into(),
            country_code: "IS".into(),
            timezone: "Atlantic/Reykjavik".into(),
            active: false,
        },
        // ──── NORTH AMERICA ────

        // ── United States (US) ──
        SiteEntry {
            unlocode: "USNYC".into(),
            name: "New York".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/New_York".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USASH".into(),
            name: "Ashburn".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/New_York".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USCHI".into(),
            name: "Chicago".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Chicago".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USDAL".into(),
            name: "Dallas".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Chicago".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USLAX".into(),
            name: "Los Angeles".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Los_Angeles".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USSFO".into(),
            name: "San Francisco".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Los_Angeles".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USSEA".into(),
            name: "Seattle".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Los_Angeles".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USPHX".into(),
            name: "Phoenix".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Phoenix".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USDEN".into(),
            name: "Denver".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/Denver".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USMIA".into(),
            name: "Miami".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/New_York".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "USATL".into(),
            name: "Atlanta".into(),
            country: "United States".into(),
            country_code: "US".into(),
            timezone: "America/New_York".into(),
            active: false,
        },
        // ── Canada (CA) ──
        SiteEntry {
            unlocode: "CA TOR".into(),
            name: "Toronto".into(),
            country: "Canada".into(),
            country_code: "CA".into(),
            timezone: "America/Toronto".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "CA VAN".into(),
            name: "Vancouver".into(),
            country: "Canada".into(),
            country_code: "CA".into(),
            timezone: "America/Vancouver".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "CA MTR".into(),
            name: "Montréal".into(),
            country: "Canada".into(),
            country_code: "CA".into(),
            timezone: "America/Toronto".into(),
            active: false,
        },
        // ──── ASIA-PACIFIC ────

        // ── Japan (JP) ──
        SiteEntry {
            unlocode: "JP TYO".into(),
            name: "Tokyo".into(),
            country: "Japan".into(),
            country_code: "JP".into(),
            timezone: "Asia/Tokyo".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "JP OSA".into(),
            name: "Osaka".into(),
            country: "Japan".into(),
            country_code: "JP".into(),
            timezone: "Asia/Tokyo".into(),
            active: false,
        },
        // ── South Korea (KR) ──
        SiteEntry {
            unlocode: "KR SEL".into(),
            name: "Seoul".into(),
            country: "South Korea".into(),
            country_code: "KR".into(),
            timezone: "Asia/Seoul".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "KR PUS".into(),
            name: "Busan".into(),
            country: "South Korea".into(),
            country_code: "KR".into(),
            timezone: "Asia/Seoul".into(),
            active: false,
        },
        // ── Singapore (SG) ──
        SiteEntry {
            unlocode: "SGSIN".into(),
            name: "Singapore".into(),
            country: "Singapore".into(),
            country_code: "SG".into(),
            timezone: "Asia/Singapore".into(),
            active: false,
        },
        // ── Hong Kong (HK) ──
        SiteEntry {
            unlocode: "HK HKG".into(),
            name: "Hong Kong".into(),
            country: "Hong Kong".into(),
            country_code: "HK".into(),
            timezone: "Asia/Hong_Kong".into(),
            active: false,
        },
        // ── Taiwan (TW) ──
        SiteEntry {
            unlocode: "TW TPE".into(),
            name: "Taipei".into(),
            country: "Taiwan".into(),
            country_code: "TW".into(),
            timezone: "Asia/Taipei".into(),
            active: false,
        },
        // ── China (CN) ──
        SiteEntry {
            unlocode: "CN SHA".into(),
            name: "Shanghai".into(),
            country: "China".into(),
            country_code: "CN".into(),
            timezone: "Asia/Shanghai".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "CN BJS".into(),
            name: "Beijing".into(),
            country: "China".into(),
            country_code: "CN".into(),
            timezone: "Asia/Shanghai".into(),
            active: false,
        },
        // ── India (IN) ──
        SiteEntry {
            unlocode: "IN BOM".into(),
            name: "Mumbai".into(),
            country: "India".into(),
            country_code: "IN".into(),
            timezone: "Asia/Kolkata".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "IN DEL".into(),
            name: "Delhi".into(),
            country: "India".into(),
            country_code: "IN".into(),
            timezone: "Asia/Kolkata".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "IN BLR".into(),
            name: "Bangalore".into(),
            country: "India".into(),
            country_code: "IN".into(),
            timezone: "Asia/Kolkata".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "IN HYD".into(),
            name: "Hyderabad".into(),
            country: "India".into(),
            country_code: "IN".into(),
            timezone: "Asia/Kolkata".into(),
            active: false,
        },
        // ── Australia (AU) ──
        SiteEntry {
            unlocode: "AU SYD".into(),
            name: "Sydney".into(),
            country: "Australia".into(),
            country_code: "AU".into(),
            timezone: "Australia/Sydney".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "AU MEL".into(),
            name: "Melbourne".into(),
            country: "Australia".into(),
            country_code: "AU".into(),
            timezone: "Australia/Melbourne".into(),
            active: false,
        },
        // ── New Zealand (NZ) ──
        SiteEntry {
            unlocode: "NZ AKL".into(),
            name: "Auckland".into(),
            country: "New Zealand".into(),
            country_code: "NZ".into(),
            timezone: "Pacific/Auckland".into(),
            active: false,
        },
        // ──── MIDDLE EAST ────

        // ── United Arab Emirates (AE) ──
        SiteEntry {
            unlocode: "AE DXB".into(),
            name: "Dubai".into(),
            country: "United Arab Emirates".into(),
            country_code: "AE".into(),
            timezone: "Asia/Dubai".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "AE AUH".into(),
            name: "Abu Dhabi".into(),
            country: "United Arab Emirates".into(),
            country_code: "AE".into(),
            timezone: "Asia/Dubai".into(),
            active: false,
        },
        // ── Saudi Arabia (SA) ──
        SiteEntry {
            unlocode: "SA RUH".into(),
            name: "Riyadh".into(),
            country: "Saudi Arabia".into(),
            country_code: "SA".into(),
            timezone: "Asia/Riyadh".into(),
            active: false,
        },
        // ── Qatar (QA) ──
        SiteEntry {
            unlocode: "QA DOH".into(),
            name: "Doha".into(),
            country: "Qatar".into(),
            country_code: "QA".into(),
            timezone: "Asia/Qatar".into(),
            active: false,
        },
        // ── Israel (IL) ──
        SiteEntry {
            unlocode: "IL TLV".into(),
            name: "Tel Aviv".into(),
            country: "Israel".into(),
            country_code: "IL".into(),
            timezone: "Asia/Jerusalem".into(),
            active: false,
        },
        // ──── SOUTH AMERICA ────

        // ── Brazil (BR) ──
        SiteEntry {
            unlocode: "BR SAO".into(),
            name: "São Paulo".into(),
            country: "Brazil".into(),
            country_code: "BR".into(),
            timezone: "America/Sao_Paulo".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "BR RIO".into(),
            name: "Rio de Janeiro".into(),
            country: "Brazil".into(),
            country_code: "BR".into(),
            timezone: "America/Sao_Paulo".into(),
            active: false,
        },
        // ── Argentina (AR) ──
        SiteEntry {
            unlocode: "AR BUE".into(),
            name: "Buenos Aires".into(),
            country: "Argentina".into(),
            country_code: "AR".into(),
            timezone: "America/Argentina/Buenos_Aires".into(),
            active: false,
        },
        // ── Chile (CL) ──
        SiteEntry {
            unlocode: "CL SCL".into(),
            name: "Santiago".into(),
            country: "Chile".into(),
            country_code: "CL".into(),
            timezone: "America/Santiago".into(),
            active: false,
        },
        // ──── AFRICA ────

        // ── South Africa (ZA) ──
        SiteEntry {
            unlocode: "ZA JNB".into(),
            name: "Johannesburg".into(),
            country: "South Africa".into(),
            country_code: "ZA".into(),
            timezone: "Africa/Johannesburg".into(),
            active: false,
        },
        SiteEntry {
            unlocode: "ZA CPT".into(),
            name: "Cape Town".into(),
            country: "South Africa".into(),
            country_code: "ZA".into(),
            timezone: "Africa/Johannesburg".into(),
            active: false,
        },
        // ── Kenya (KE) ──
        SiteEntry {
            unlocode: "KE NBO".into(),
            name: "Nairobi".into(),
            country: "Kenya".into(),
            country_code: "KE".into(),
            timezone: "Africa/Nairobi".into(),
            active: false,
        },
        // ── Nigeria (NG) ──
        SiteEntry {
            unlocode: "NG LOS".into(),
            name: "Lagos".into(),
            country: "Nigeria".into(),
            country_code: "NG".into(),
            timezone: "Africa/Lagos".into(),
            active: false,
        },
    ]
}

static SITE_STORE: std::sync::LazyLock<Mutex<Vec<RegisteredSite>>> =
    std::sync::LazyLock::new(|| {
        let sites = reference_sites()
            .into_iter()
            .map(|mut site| {
                site.unlocode = normalize_site_code(&site.unlocode, SiteCodeSystem::Unlocode)
                    .expect("built-in UN/LOCODE seed must be valid");
                RegisteredSite {
                    site,
                    code_system: SiteCodeSystem::Unlocode,
                }
            })
            .collect();
        Mutex::new(sites)
    });

fn site_store() -> &'static Mutex<Vec<RegisteredSite>> {
    &SITE_STORE
}

fn site_json(entry: &RegisteredSite) -> Value {
    json!({
        "code": entry.site.unlocode,
        "code_system": entry.code_system.as_str(),
        // Backward-compatible alias for existing API clients.
        "unlocode": entry.site.unlocode,
        "name": entry.site.name,
        "country": entry.site.country,
        "country_code": entry.site.country_code,
        "timezone": entry.site.timezone,
        "active": entry.site.active
    })
}

fn normalize_registration(
    mut site: SiteEntry,
    code_system: SiteCodeSystem,
) -> Result<RegisteredSite, String> {
    site.unlocode = normalize_site_code(&site.unlocode, code_system)?;
    Ok(RegisteredSite { site, code_system })
}

/// Register a site in the process-local store. Codes share one canonical
/// namespace across systems, so case/spelling aliases and cross-system
/// collisions are rejected.
pub fn register_site(site: SiteEntry, code_system: SiteCodeSystem) -> Result<Value, String> {
    let entry = normalize_registration(site, code_system)?;
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    if store
        .iter()
        .any(|existing| existing.site.unlocode == entry.site.unlocode)
    {
        return Err(format!("Site '{}' already exists", entry.site.unlocode));
    }
    let mut result = site_json(&entry);
    result["source"] = json!("dry-run");
    store.push(entry);
    Ok(result)
}

/// Replace or insert a site loaded from durable storage. Used during startup
/// hydration and immediately after a committed database registration.
pub fn upsert_site(site: SiteEntry, code_system: SiteCodeSystem) -> Result<(), String> {
    let entry = normalize_registration(site, code_system)?;
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    if let Some(existing) = store
        .iter_mut()
        .find(|existing| existing.site.unlocode == entry.site.unlocode)
    {
        *existing = entry;
    } else {
        store.push(entry);
    }
    Ok(())
}

pub fn list_sites(active_only: bool) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let sites: Vec<Value> = store
        .iter()
        .filter(|entry| !active_only || entry.site.active)
        .map(site_json)
        .collect();
    Ok(json!({"source": "dry-run", "count": sites.len(), "sites": sites}))
}

pub fn get_site(code: &str) -> Result<Value, String> {
    let code = normalize_site_code_for_lookup(code)?;
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let entry = store
        .iter()
        .find(|entry| entry.site.unlocode == code)
        .ok_or_else(|| format!("Site '{}' not found", code))?;
    let mut result = site_json(entry);
    result["source"] = json!("dry-run");
    Ok(result)
}

pub fn activate_site(code: &str) -> Result<Value, String> {
    let code = normalize_site_code_for_lookup(code)?;
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    let entry = store
        .iter_mut()
        .find(|entry| entry.site.unlocode == code)
        .ok_or_else(|| format!("Site '{}' not found in registry", code))?;
    entry.site.active = true;
    Ok(json!({
        "source": "dry-run",
        "code": entry.site.unlocode,
        "code_system": entry.code_system.as_str(),
        "unlocode": entry.site.unlocode,
        "name": entry.site.name,
        "active": true,
        "message": format!("Site {} ({}) activated", entry.site.unlocode, entry.site.name)
    }))
}

pub fn deactivate_site(code: &str) -> Result<Value, String> {
    let code = normalize_site_code_for_lookup(code)?;
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    let entry = store
        .iter_mut()
        .find(|entry| entry.site.unlocode == code)
        .ok_or_else(|| format!("Site '{}' not found", code))?;
    entry.site.active = false;
    Ok(json!({
        "source": "dry-run",
        "code": entry.site.unlocode,
        "code_system": entry.code_system.as_str(),
        "unlocode": entry.site.unlocode,
        "name": entry.site.name,
        "active": false,
        "message": format!("Site {} ({}) deactivated", entry.site.unlocode, entry.site.name)
    }))
}

pub fn search_sites(query: &str) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let q = query.to_lowercase();
    let matches: Vec<Value> = store
        .iter()
        .filter(|entry| {
            entry.site.unlocode.to_lowercase().contains(&q)
                || entry.site.name.to_lowercase().contains(&q)
                || entry.site.country.to_lowercase().contains(&q)
                || entry.site.country_code.to_lowercase() == q
        })
        .map(site_json)
        .collect();
    Ok(json!({"source": "dry-run", "query": query, "count": matches.len(), "matches": matches}))
}

// ─── Country hierarchy endpoints ───

pub fn list_countries() -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let mut countries: std::collections::BTreeMap<String, (String, usize)> =
        std::collections::BTreeMap::new();
    for entry in store.iter() {
        let s = &entry.site;
        let entry = countries
            .entry(s.country_code.clone())
            .or_insert((s.country.clone(), 0));
        entry.1 += 1;
    }
    let result: Vec<Value> = countries
        .into_iter()
        .map(|(code, (name, count))| {
            json!({"country_code": code, "country": name, "site_count": count})
        })
        .collect();
    Ok(json!({"source": "dry-run", "count": result.len(), "countries": result}))
}

pub fn list_cities_by_country(country_code: &str) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let cc = country_code.to_uppercase();
    let cities: Vec<Value> = store
        .iter()
        .filter(|entry| entry.site.country_code.to_uppercase() == cc)
        .map(site_json)
        .collect();
    if cities.is_empty() {
        return Err(format!("No sites found for country code '{}'", cc));
    }
    Ok(json!({"source": "dry-run", "country_code": cc, "count": cities.len(), "cities": cities}))
}

pub fn get_active_site_codes() -> Result<Vec<String>, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    Ok(store
        .iter()
        .filter(|entry| entry.site.active)
        .map(|entry| entry.site.unlocode.clone())
        .collect())
}

pub fn get_active_site_names() -> Result<Vec<String>, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    Ok(store
        .iter()
        .filter(|entry| entry.site.active)
        .map(|entry| entry.site.name.clone())
        .collect())
}

pub fn is_valid_site(code: &str) -> bool {
    let Ok(code) = normalize_site_code_for_lookup(code) else {
        return false;
    };
    site_store()
        .lock()
        .map(|store| {
            store
                .iter()
                .any(|entry| entry.site.unlocode == code && entry.site.active)
        })
        .unwrap_or(false)
}

/// True when `code` is a RECOGNISED site in the registry, regardless of its
/// active status — i.e. membership only. Unlike [`is_valid_site`] (which also
/// requires the site to be ACTIVE/operational), this answers "is this a known,
/// governed site code?". A CMDB record can legitimately reference a recognised but
/// currently-inactive site, so import validation uses this rather than the
/// active-only check. Membership is also stable against runtime activate/
/// deactivate toggling of the registry.
pub fn is_known_site(code: &str) -> bool {
    let Ok(code) = normalize_site_code_for_lookup(code) else {
        return false;
    };
    site_store()
        .lock()
        .map(|store| store.iter().any(|entry| entry.site.unlocode == code))
        .unwrap_or(false)
}

/// Hydrate the static site store with persisted active states from the DB.
///
/// Called once at API startup after the DB connection is established.
/// For each (unlocode, active) pair, updates the matching entry in the
/// static store; unknown unlocodes are silently ignored.
/// This function is I/O-free — the caller loads the states and passes them in.
pub fn hydrate_active_states(states: &[(String, bool)]) {
    let Ok(mut store) = site_store().lock() else {
        return;
    };
    for (unlocode, active) in states {
        let Ok(code) = normalize_site_code_for_lookup(unlocode) else {
            continue;
        };
        if let Some(entry) = store.iter_mut().find(|entry| entry.site.unlocode == code) {
            entry.site.active = *active;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that mutate or read a specific site's ACTIVE flag share the
    // process-wide `SITE_STORE`. Serialize them so `test_activate_deactivate`'s
    // transient ESMAD activation cannot race the `!is_valid_site("ESMAD")`
    // readers under parallel execution (a pre-existing flake that intermittently
    // reddened CI). Poison-safe: a panicking guarded test must not cascade-fail
    // the others.
    static ACTIVE_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_list_all_sites() {
        let result = list_sites(false).unwrap();
        assert!(result["count"].as_u64().unwrap() >= 80);
    }

    #[test]
    fn test_list_active_only() {
        let result = list_sites(true).unwrap();
        let sites = result["sites"].as_array().unwrap();
        for s in sites {
            assert!(s["active"].as_bool().unwrap());
        }
    }

    #[test]
    fn test_get_site_found() {
        let result = get_site("DEFRA").unwrap();
        assert_eq!(result["name"], "Frankfurt");
        assert_eq!(result["country_code"], "DE");
    }

    #[test]
    fn test_get_site_not_found() {
        assert!(get_site("NONEXISTENT").is_err());
    }

    #[test]
    fn site_codes_have_one_safe_canonical_spelling() {
        assert_eq!(
            normalize_site_code(" jp tyo ", SiteCodeSystem::Unlocode).unwrap(),
            "JPTYO"
        );
        assert_eq!(
            normalize_site_code(" dc-eu_01.prod ", SiteCodeSystem::Custom).unwrap(),
            "DC-EU_01.PROD"
        );
        for invalid in ["A", "DC/EU", "-DC01", "DC01-", "DC EU", "DÇ01"] {
            assert!(
                normalize_site_code(invalid, SiteCodeSystem::Custom).is_err(),
                "{invalid} must not be accepted as a custom site code"
            );
        }
    }

    #[test]
    fn active_custom_site_is_registered_in_the_same_governed_namespace() {
        let code = "TEST-REGISTRY-01";
        let _ = register_site(
            SiteEntry {
                unlocode: code.into(),
                name: "Registry test site".into(),
                country: "Belgium".into(),
                country_code: "BE".into(),
                timezone: "Europe/Brussels".into(),
                active: true,
            },
            SiteCodeSystem::Custom,
        );
        assert!(is_known_site("test-registry-01"));
        assert!(is_valid_site(code));
        let result = get_site(code).unwrap();
        assert_eq!(result["code_system"], "custom");
        assert_eq!(result["code"], code);
        assert!(
            register_site(
                SiteEntry {
                    unlocode: code.to_ascii_lowercase(),
                    name: "Alias".into(),
                    country: "Belgium".into(),
                    country_code: "BE".into(),
                    timezone: "Europe/Brussels".into(),
                    active: false,
                },
                SiteCodeSystem::Custom,
            )
            .is_err(),
            "case aliases must collide with the canonical code"
        );
    }

    #[test]
    fn test_activate_deactivate() {
        let _guard = ACTIVE_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let activate_result = activate_site("ESMAD").unwrap();
        assert!(activate_result["active"].as_bool().unwrap());
        let deactivate_result = deactivate_site("ESMAD").unwrap();
        assert!(!deactivate_result["active"].as_bool().unwrap());
        let _ = deactivate_site("ESMAD");
    }

    #[test]
    fn test_search_by_city() {
        let result = search_sites("Frankfurt").unwrap();
        assert_eq!(result["count"].as_u64().unwrap(), 1);
        assert_eq!(result["matches"][0]["unlocode"], "DEFRA");
    }

    #[test]
    fn test_search_by_country() {
        let result = search_sites("Netherlands").unwrap();
        assert!(result["count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_search_by_country_code() {
        let result = search_sites("DE").unwrap();
        assert!(result["count"].as_u64().unwrap() >= 4);
    }

    #[test]
    fn test_get_active_site_codes() {
        let codes = get_active_site_codes().unwrap();
        assert!(codes.contains(&"DEFRA".to_string()));
        assert!(codes.contains(&"GBLON".to_string()));
    }

    #[test]
    fn test_is_valid_site() {
        let _guard = ACTIVE_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(is_valid_site("DEFRA"));
        assert!(!is_valid_site("NONEXISTENT"));
        assert!(!is_valid_site("ESMAD"));
    }

    #[test]
    fn test_is_known_site_is_membership_not_active() {
        let _guard = ACTIVE_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // is_known_site is membership-only: an active site AND a recognised but
        // inactive site both count; only a truly-unrecognised code does not.
        assert!(is_known_site("DEFRA")); // active
        assert!(is_known_site("ESMAD")); // recognised but inactive (is_valid_site is false)
        assert!(!is_valid_site("ESMAD")); // distinction: active-only check rejects it
        assert!(!is_known_site("NONEXISTENT"));
    }

    #[test]
    fn test_list_countries() {
        let result = list_countries().unwrap();
        assert!(result["count"].as_u64().unwrap() >= 20);
        let countries = result["countries"].as_array().unwrap();
        let de = countries
            .iter()
            .find(|c| c["country_code"] == "DE")
            .unwrap();
        assert_eq!(de["country"], "Germany");
    }

    #[test]
    fn test_list_cities_by_country() {
        let result = list_cities_by_country("DE").unwrap();
        assert_eq!(result["country_code"], "DE");
        assert!(result["count"].as_u64().unwrap() >= 4);
    }

    #[test]
    fn test_list_cities_invalid_country() {
        assert!(list_cities_by_country("XX").is_err());
    }

    #[test]
    fn test_hydrate_active_states() {
        // Use FRPAR (active by default) and FRMRS (inactive by default).
        // Neither is asserted by name in any other parallel test, so these
        // flips cannot race with test_is_valid_site or test_activate_deactivate.
        hydrate_active_states(&[("FRPAR".to_string(), false), ("FRMRS".to_string(), true)]);
        // is_valid_site and get_active_site_codes must reflect the hydration.
        assert!(
            !is_valid_site("FRPAR"),
            "FRPAR should be inactive after hydrate"
        );
        assert!(
            is_valid_site("FRMRS"),
            "FRMRS should be active after hydrate"
        );
        let codes = get_active_site_codes().unwrap();
        assert!(!codes.contains(&"FRPAR".to_string()));
        assert!(codes.contains(&"FRMRS".to_string()));
        // Restore original state so other tests are not affected.
        hydrate_active_states(&[("FRPAR".to_string(), true), ("FRMRS".to_string(), false)]);
    }
}
