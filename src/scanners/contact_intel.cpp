/// @file scanners/contact_intel.cpp
/// @brief Contact intelligence: WhatsApp profile scraping (no rate limit),
///        vCard/contact page harvesting, out-of-office auto-reply probing,
///        and exposed communication metadata.
///
/// WhatsApp leaks without rate limiting:
///   - Profile photo (even if "contacts only" — often misconfigured)
///   - About/status text (business hours, personal info, vacation notices)
///   - Online/last seen status (activity patterns)
///   - Business profiles: address, email, website, category, hours
///   - Group membership via invite link scraping
///
/// Out-of-office / auto-reply leaks:
///   - Internal org structure (manager names, team names)
///   - Vacation dates (social engineering window)
///   - Alternate contacts (secondary targets)
///   - Internal systems mentioned (ticketing, project names)
///   - Phone numbers / personal emails
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// Scrape WhatsApp business profile via wa.me API (no auth, no rate limit).
std::vector<Finding> scan_whatsapp_intel(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // 1. Find phone numbers on the target website.
  std::set<std::string> phones;
  auto home = http.get(base + "/");
  // Match international phone formats.
  std::regex phone_re(R"((?:\+|00)[1-9]\d{7,14})");
  std::string body = home.body;
  std::sregex_iterator it(body.begin(), body.end(), phone_re);
  for (; it != std::sregex_iterator(); ++it)
    phones.insert((*it)[0].str());

  // Also check contact/about pages.
  const std::vector<std::string> contact_paths = {
      "/contact", "/about", "/impressum", "/kontakt", "/contacto",
      "/contact-us", "/about-us", "/team", "/support"};
  for (const auto &path : contact_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code != 200) continue;
    std::sregex_iterator pit(resp.body.begin(), resp.body.end(), phone_re);
    for (; pit != std::sregex_iterator(); ++pit)
      phones.insert((*pit)[0].str());
  }

  // 2. Check each phone on WhatsApp (wa.me has no rate limiting).
  for (const auto &phone : phones) {
    std::string clean = phone;
    // Strip + and spaces.
    clean.erase(std::remove_if(clean.begin(), clean.end(),
                               [](char c) { return !isdigit(c); }),
                clean.end());

    // wa.me redirect check — confirms WhatsApp registration.
    std::string wa_url = "https://wa.me/" + clean;
    auto resp = http.get(wa_url);
    if (resp.status_code == 200 &&
        resp.body.find("api.whatsapp.com") != std::string::npos) {
      findings.push_back({"WhatsApp Confirmed", "info", wa_url,
                          "Phone " + phone + " is registered on WhatsApp",
                          "", "", ""});
    }

    // WhatsApp Business API catalog (public, no auth).
    std::string biz_url = "https://wa.me/c/" + clean;
    auto biz = http.get(biz_url);
    if (biz.status_code == 200 && biz.body.size() > 500) {
      std::string detail = "WhatsApp Business profile found";
      // Extract business info.
      if (biz.body.find("address") != std::string::npos)
        detail += " — address exposed";
      if (biz.body.find("email") != std::string::npos)
        detail += " — email exposed";
      if (biz.body.find("website") != std::string::npos)
        detail += " — website linked";
      findings.push_back({"WhatsApp Business Profile", "medium", biz_url,
                          detail, "", phone, ""});
    }
  }

  // 3. Look for WhatsApp group invite links (leaked on website).
  std::regex wa_group_re(R"(https://chat\.whatsapp\.com/[A-Za-z0-9]{20,})");
  auto grp_begin = std::sregex_iterator(home.body.begin(), home.body.end(), wa_group_re);
  for (auto gi = grp_begin; gi != std::sregex_iterator(); ++gi) {
    std::string link = (*gi)[0].str();
    auto gresp = http.get(link);
    if (gresp.status_code == 200) {
      std::string group_name = "unknown";
      size_t pos = gresp.body.find("og:title\" content=\"");
      if (pos != std::string::npos) {
        pos += 19;
        size_t end = gresp.body.find("\"", pos);
        if (end != std::string::npos)
          group_name = gresp.body.substr(pos, end - pos);
      }
      findings.push_back({"WhatsApp Group Leak", "high", link,
                          "Public WhatsApp group invite: " + group_name,
                          "", "", ""});
    }
  }

  return findings;
}

/// Probe for out-of-office / auto-reply information leakage.
std::vector<Finding> scan_ooo_probing(const Config &cfg, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // 1. Harvest email addresses from the target.
  std::set<std::string> emails;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  std::regex email_re("[a-zA-Z0-9._%+\\-]+@" + domain);
  const std::vector<std::string> pages = {
      "/", "/contact", "/about", "/team", "/impressum", "/support"};
  for (const auto &path : pages) {
    auto resp = http.get(base + path);
    std::sregex_iterator it(resp.body.begin(), resp.body.end(), email_re);
    for (; it != std::sregex_iterator(); ++it)
      emails.insert((*it)[0].str());
  }

  // Also try common patterns.
  const std::vector<std::string> prefixes = {
      "info", "contact", "support", "admin", "hr", "sales",
      "office", "hello", "team", "security"};
  for (const auto &p : prefixes)
    emails.insert(p + "@" + domain);

  // 2. Check for Exchange/O365 autodiscover (reveals OOO config).
  auto autodiscover = http.get("https://autodiscover." + domain +
                               "/autodiscover/autodiscover.xml");
  if (autodiscover.status_code == 200 || autodiscover.status_code == 401) {
    findings.push_back({"Autodiscover Exposed", "medium",
                        "https://autodiscover." + domain,
                        "Exchange Autodiscover endpoint reachable — "
                        "can be used for credential harvesting",
                        "", "", ""});
  }

  // 3. Check OWA for OOO indicators.
  auto owa = http.get("https://mail." + domain + "/owa/");
  if (owa.status_code == 200 || owa.status_code == 302) {
    findings.push_back({"OWA Exposed", "medium",
                        "https://mail." + domain + "/owa/",
                        "Outlook Web Access reachable — OOO replies "
                        "leak org structure when emails are sent",
                        "", "", ""});
  }

  // 4. Check for EWS (Exchange Web Services) — can query OOO status.
  auto ews = http.get("https://mail." + domain + "/EWS/Exchange.asmx");
  if (ews.status_code == 200 || ews.status_code == 401) {
    findings.push_back({"EWS Exposed", "high",
                        "https://mail." + domain + "/EWS/Exchange.asmx",
                        "Exchange Web Services reachable — GetUserOofSettings "
                        "can extract OOO messages with valid creds",
                        "", "", ""});
  }

  // 5. Check Microsoft 365 tenant info (public, no auth).
  auto tenant = http.get("https://login.microsoftonline.com/" + domain +
                         "/.well-known/openid-configuration");
  if (tenant.status_code == 200 &&
      tenant.body.find("token_endpoint") != std::string::npos) {
    findings.push_back({"M365 Tenant Confirmed", "info",
                        "https://login.microsoftonline.com/" + domain,
                        "Microsoft 365 tenant exists — OOO auto-replies "
                        "will respond to any sender by default",
                        "", "", ""});
  }

  // 6. Check for contact form auto-responders (leak internal info).
  for (const auto &form : crawl.forms) {
    if (form.method != "POST") continue;
    bool has_email_field = false;
    for (const auto &f : form.fields) {
      if (f.name.find("email") != std::string::npos ||
          f.name.find("mail") != std::string::npos) {
        has_email_field = true;
        break;
      }
    }
    if (has_email_field) {
      findings.push_back({"Contact Form Auto-Reply", "info", form.action,
                          "Contact form found — auto-reply may leak "
                          "employee names, ticket systems, response times",
                          "", "", ""});
    }
  }

  return findings;
}

/// Harvest exposed contact/vCard data.
std::vector<Finding> scan_contact_harvest(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for vCard/contact exports.
  const std::vector<std::string> vcard_paths = {
      "/contact.vcf", "/team.vcf", "/contacts.vcf",
      "/staff.vcf", "/.well-known/carddav"};
  for (const auto &path : vcard_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("BEGIN:VCARD") != std::string::npos ||
         resp.body.find("FN:") != std::string::npos)) {
      findings.push_back({"vCard Exposed", "medium", base + path,
                          "vCard file with contact details publicly accessible",
                          "", "", ""});
    }
  }

  // Check for staff/team directory pages leaking too much.
  const std::vector<std::string> dir_paths = {
      "/team", "/staff", "/people", "/directory", "/our-team",
      "/about/team", "/employees"};
  for (const auto &path : dir_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code != 200 || resp.body.size() < 200) continue;

    int signals = 0;
    if (resp.body.find("@") != std::string::npos) signals++;
    if (std::regex_search(resp.body, std::regex(R"(\+\d{10,})"))) signals++;
    if (resp.body.find("linkedin.com") != std::string::npos) signals++;
    if (resp.body.find("extension") != std::string::npos) signals++;

    if (signals >= 2) {
      findings.push_back({"Staff Directory Exposed", "medium", base + path,
                          "Team page leaks emails + phone numbers + social profiles",
                          "", "", ""});
    }
  }

  // Check for CalDAV/CardDAV (calendar/contact sync — often misconfigured).
  auto caldav = http.get(base + "/.well-known/caldav");
  if (caldav.status_code == 200 || caldav.status_code == 301) {
    findings.push_back({"CalDAV Exposed", "medium", base + "/.well-known/caldav",
                        "CalDAV endpoint reachable — may expose calendar data "
                        "including OOO schedules",
                        "", "", ""});
  }

  return findings;
}

} // namespace

std::vector<Scanner> register_contact_intel_scanners() {
  return {
      {"WhatsApp Intel", scan_whatsapp_intel},
      {"OOO/Auto-Reply Probing", scan_ooo_probing},
      {"Contact Harvest", scan_contact_harvest},
  };
}

} // namespace apex
