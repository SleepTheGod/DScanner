import requests
from bs4 import BeautifulSoup

# ------------------------------
# List of sensitive files, directories, and admin endpoints
# ------------------------------
sensitive_paths = [
    # Core Drupal paths
    "core/install.php", "core/authorize.php", "core/rebuild.php", "core/modules/statistics/statistics.php",
    "core/modules/system/tests/https.php", "core/modules/system/tests/http.php", "autoload.php",
    "composer.json", "composer.lock", ".git", ".svn", ".DS_Store", ".well-known",
    "CHANGELOG.txt", "INSTALL.txt", "LICENSE.txt", "MAINTAINERS.txt", "README.txt", "UPGRADE.txt",
    "phpinfo.php", ".htaccess", "robots.txt", "web.config", ".env", ".htpasswd",
    "includes", "misc", "modules", "profiles", "scripts", "sites", "themes",
    
    # Admin paths
    "/admin", "/admin/config", "/admin/config/system", "/admin/config/people", "/admin/config/media",
    "/admin/appearance", "/admin/modules", "/admin/content", "/admin/reports", "/admin/structure",
    "/admin/structure/block", "/admin/structure/taxonomy", "/admin/structure/views", "/admin/structure/menu",
    "/admin/structure/paragraphs", "/admin/structure/layout", "/admin/structure/search",
    "/admin/structure/entity", "/admin/structure/migrate", "/admin/structure/fields", "/admin/structure/users",
    "/admin/structure/custom-blocks", "/admin/config/services", "/admin/config/media/image-style",
    "/admin/config/system/performance", "/admin/config/system/smtp", "/admin/config/search/search-api",
    "/admin/config/search/search-api/index", "/admin/config/search/search-api/server",
    "/admin/config/development/logging", "/admin/config/development/cache", "/admin/config/development/performance",
    "/admin/config/development/debugging", "/admin/config/development/redis", "/admin/config/development/override",
    "/admin/config/development/agentrace", "/admin/config/people/accounts", "/admin/config/people/password-policy",
    "/admin/config/people/roles", "/admin/config/people/permissions", "/admin/config/people/registration",
    "/admin/config/people/session", "/admin/config/people/login", "/admin/config/people/accounts/form",
    "/admin/config/people/roles/permissions", "/admin/config/people/roles/create", "/admin/config/people/roles/update",
    "/admin/config/people/roles/delete",
    
    # Content and nodes
    "/admin/content/{content_type}", "/admin/content/{content_type}/add",
    "/admin/content/{content_type}/edit/{node_id}", "/admin/content/{content_type}/delete/{node_id}",
    "/node/add", "/node/add/article", "/node/add/page", "/node/add/story",
    "/node/{nid}/edit", "/node/{nid}/delete", "/node/{nid}/view",

    # User endpoints
    "/user/login", "/user/logout", "/user/register", "/user/password",
    "/user/{uid}", "/user/{uid}/edit", "/user/{uid}/delete", "/user/{uid}/roles",
    "/user/{uid}/access", "/user/{uid}/content", "/user/{uid}/settings",
    "/user/{uid}/session", "/user/{uid}/password", "/user/{uid}/profile",
    "/user/{uid}/subscriptions", "/user/{uid}/posts", "/user/{uid}/comments",
    "/user/{uid}/notifications", "/user/{uid}/messages", "/user/{uid}/inbox",
    "/user/{uid}/outbox", "/user/{uid}/activity",

    # Core system paths
    "/core", "/core/misc", "/core/scripts", "/core/vendor", "/core/lib", "/core/themes", "/core/assets",
    "/sites/default/files/", "/sites/default/private/", "/sites/default/settings.php", "/sites/default/cron.php",

    # REST and entity endpoints
    "/rest/session/token", "/rest/views/{view_name}/page", "/rest/views/{view_name}/json",
    "/rest/views/{view_name}/rss", "/rest/views/{view_name}/xml", "/rest/{resource_name}",
    "/rest/{resource_name}/{id}", "/entity/{entity_type}/{id}", "/entity/{entity_type}/{id}/edit",
    "/entity/{entity_type}/{id}/delete", "/entity/{entity_type}/{id}/view", "/entity/{entity_type}/{id}/field",
    "/entity/{entity_type}/{id}/permissions", "/entity/{entity_type}/{id}/assign",
    "/entity/{entity_type}/{id}/parent", "/entity/{entity_type}/{id}/content",
    "/entity/{entity_type}/{id}/custom-fields", "/entity/{entity_type}/create",
    "/entity/{entity_type}/update", "/entity/{entity_type}/delete", "/entity/{entity_type}/views",
    "/entity/{entity_type}/manage", "/entity/{entity_type}/settings", "/entity/{entity_type}/rules",
    "/entity/{entity_type}/translations", "/entity/{entity_type}/variants", "/entity/{entity_type}/taxonomy",
    "/entity/{entity_type}/comments", "/entity/{entity_type}/comment-form", "/entity/{entity_type}/fields",
    "/entity/{entity_type}/view-form", "/entity/{entity_type}/create-form", "/entity/{entity_type}/edit-form",
    "/entity/{entity_type}/delete-form", "/entity/{entity_type}/field-edit", "/entity/{entity_type}/assign-roles",
    "/entity/{entity_type}/add-field", "/entity/{entity_type}/update-field", "/entity/{entity_type}/remove-field",
    "/entity/{entity_type}/update-permissions", "/entity/{entity_type}/parent/{parent_id}", "/entity/{entity_type}/children",
    "/entity/{entity_type}/structure", "/entity/{entity_type}/select", "/entity/{entity_type}/views/{view_name}",
    "/entity/{entity_type}/field/{field_name}", "/entity/{entity_type}/field/{field_name}/add",
    "/entity/{entity_type}/field/{field_name}/edit", "/entity/{entity_type}/field/{field_name}/delete",
    "/entity/{entity_type}/field/{field_name}/view", "/entity/{entity_type}/field/{field_name}/settings",
    "/entity/{entity_type}/field/{field_name}/permissions", "/entity/{entity_type}/field/{field_name}/value",
    "/entity/{entity_type}/field/{field_name}/translations", "/entity/{entity_type}/field/{field_name}/text",
    "/entity/{entity_type}/field/{field_name}/field-type", "/entity/{entity_type}/field/{field_name}/create",
    "/entity/{entity_type}/field/{field_name}/update", "/entity/{entity_type}/field/{field_name}/remove",
    "/entity/{entity_type}/field/{field_name}/delete-form", "/entity/{entity_type}/field/{field_name}/add-field",
    "/entity/{entity_type}/field/{field_name}/field-edit", "/entity/{entity_type}/field/{field_name}/edit-form",
    "/entity/{entity_type}/field/{field_name}/update-form", "/entity/{entity_type}/field/{field_name}/translations-form",
    "/entity/{entity_type}/field/{field_name}/delete-form", "/entity/{entity_type}/field/{field_name}/view-form",
    "/entity/{entity_type}/field/{field_name}/field-definition", "/entity/{entity_type}/field/{field_name}/create-form",
    "/entity/{entity_type}/field/{field_name}/edit-form", "/entity/{entity_type}/field/{field_name}/remove-form",
    "/entity/{entity_type}/field/{field_name}/view", "/entity/{entity_type}/field/{field_name}/permissions",
    "/entity/{entity_type}/field/{field_name}/field-type-form", "/entity/{entity_type}/field/{field_name}/field-definitions",
    "/entity/{entity_type}/field/{field_name}/value-form", "/entity/{entity_type}/field/{field_name}/text-form",
    "/entity/{entity_type}/field/{field_name}/value", "/entity/{entity_type}/field/{field_name}/remove",
    "/entity/{entity_type}/field/{field_name}/field-definition-form", "/entity/{entity_type}/field/{field_name}/permissions-form",
    "/robots.txt", "/crossdomain.xml", "/xmlrpc.php", "/update.php", "/about", "/help", "/donate",
    "/terms-of-service", "/privacy-policy", "/404"
]

# ------------------------------
# Security headers to check
# ------------------------------
security_headers = [
    "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
    "Content-Security-Policy", "Strict-Transport-Security"
]

# ------------------------------
# Scan function
# ------------------------------
def scan_website(url):
    print("[DRUPAL VULNERABILITY SCAN]")

    print(f"[INFO] Scanning website: {url}\n")

    try:
        response = requests.get(url)
        headers = response.headers

        # Check for security headers
        print("[SECURITY HEADERS]")
        for header in security_headers:
            if header in headers:
                print(f"[+] {header} is present")
            else:
                print(f"[-] {header} is missing")

        # Check for sensitive files and endpoints
        print("\n[SENSITIVE FILES & ENDPOINTS]")
        for path in sensitive_paths:
            full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
            try:
                r = requests.get(full_url)
                if r.status_code == 200:
                    print(f"[+] Accessible: {full_url}")
                else:
                    print(f"[-] Not found: {full_url}")
            except requests.RequestException as e:
                print(f"[ERROR] Unable to check {full_url}: {str(e)}")

        # Directory listing check
        print("\n[DIRECTORY LISTING]")
        if "Index of" in response.text:
            print("[!] Directory listing is enabled.")
        else:
            print("[+] Directory listing is disabled.")

    except requests.RequestException as e:
        print(f"[ERROR] Failed to scan {url}: {str(e)}")


# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the target URL (e.g., http://example.com): ")
    scan_website(target_url)
