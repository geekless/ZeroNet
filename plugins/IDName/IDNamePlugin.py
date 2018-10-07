import logging
import re
import time

from Config import config
from Plugin import PluginManager

allow_reload = False  # No reload supported

log = logging.getLogger("IDNamePlugin")

class IDNameResolver(object):
    cache = None
    site_zeroid = None

    def __init__(self, site_manager, zeroid_address):
        self.site_manager = site_manager
        self.zeroid_address = zeroid_address

    def getSite(self, domain):
        return self.site_manager.get(domain)

    def needSite(self, domain):
        return self.site_manager.need(domain)

    def lookupCache(self, domain):
        if not self.cache:
            self.cache = {}

        entry = self.cache.get(domain)
        if not entry:
            return None

        timestamp = entry.get("timestamp", 0)
        provider_modified = entry.get("provider_modified", 0)
        provider_address = entry.get("provider_address", None)
        valid = False

        current_time = time.time()

        # force invalidation, if the record is too old or the system time was shifted back
        if timestamp and timestamp >= current_time or timestamp < current_time - 60 * 30:
            timestamp = 0
            provider_modified = 0

        if timestamp and provider_modified:
            provider_age = current_time - provider_modified
            ttl = 1
            if   provider_age > 60 * 60 * 24 * 10:
                ttl = 60 * 5
            elif provider_age > 60 * 60 * 24:
                ttl = 60
            elif provider_age > 60 * 60:
                ttl = 10
            elif provider_age > 60:
                ttl = 5

            if timestamp + ttl > current_time:
                valid = True

        if not valid and provider_address and provider_modified:
            provider = self.site_manager.get(provider_address)
            if provider and provider.content_manager:
                modified = provider.content_manager.contents.get("content.json", {}).get("modified", 0)
                if modified == provider_modified:
                    valid = True

        if not valid:
            self.cache[domain] = None

        return self.cache.get(domain)

    def saveInCache(self, entry):
        entry["timestamp"] = time.time()
        self.cache[entry["domain"]] = entry

    def load(self):
        if not self.site_manager.get(self.zeroid_address):
            self.site_manager.need(self.zeroid_address)

    # Return: True if the address is .zeroid domain
    def isIDDomain(self, address):
        return re.match("(.*?)([A-Za-z0-9_-]+\.zeroid)$", address)

    def getDataFileList(self):
        return filter(
            lambda x: re.match("data/.*\.json$", x),
            self.site_zeroid.content_manager.contents.get("content.json", {}).get("files", {}).keys()
        )

    def resolveIDDomainFromFile(self, domain, file_name, allow_recursion = True):
        self.site_zeroid.needFile(file_name, priority=10)

        r = re.search("(.*?)([A-Za-z0-9_-]+)\.zeroid$", domain)
        subdomain = r.group(1)
        user_id = r.group(2)

        data = self.site_zeroid.storage.loadJson(file_name)
        certs  = data.get("users", data.get("certs"))
        if not certs:
            return None

        cert = certs.get(user_id)
        if not cert:
            return None

        if cert.startswith("@") and allow_recursion:
            r = cert[1:].split(',')
            cert_file_name = "data/certs_%s.json" % r[0]
            return self.resolveIDDomainFromFile(domain, cert_file_name, allow_recursion = False)

        r = cert.split(',')
        return r[1]

    def resolveIDDomainNoCache(self, domain):
        provider_address = self.zeroid_address
        if not self.site_zeroid:
            self.site_zeroid = self.needSite(provider_address)

        provider_modified = self.site_zeroid.content_manager.contents.get("content.json", {}).get("modified", 0)

        address = None
        for data_file_name in self.getDataFileList():
            address = self.resolveIDDomainFromFile(domain, data_file_name)
            if address:
                break

        entry = {}
        entry["domain"] = domain
        entry["address"] = address
        entry["provider_address"] = provider_address
        entry["provider_modified"] = provider_modified
        return entry

    # Resolve domain
    # Return: The address or None
    def resolveIDDomain(self, domain):
        domain = domain.lower()

        entry = self.lookupCache(domain)
        if entry:
            log.info("cache: %s -> %s", domain, entry["address"])
            return entry["address"]

        r = re.search("(.*?)([A-Za-z0-9_-]+\.zeroid)$", domain)
        subdomain = r.group(1)
        plain_domain = r.group(2)

        entry = self.lookupCache(plain_domain)
        if not entry:
            entry = self.resolveIDDomainNoCache(plain_domain)
            self.saveInCache(entry)

        if domain != plain_domain and entry["address"]:
            entry = self.resolveSubdomain(domain, entry["address"])
            self.saveInCache(entry)

        return entry["address"]


    def resolveSubdomain(self, domain, provider_address):
        entry = {}
        entry["domain"] = domain
        entry["address"] = None
        entry["provider_address"] = provider_address
        entry["provider_modified"] = 0

        if not provider_address:
            return entry

        for i in xrange(60):
            log.info("resolveSubdomain: %s: waiting for data: %s (%d)", domain, provider_address, i)
            provider = self.site_manager.need(provider_address)
            if provider:
                provider.needFile("content.json", priority=10)
                content_json = provider.content_manager.contents.get("content.json", {})
                if content_json:
                    break
            time.sleep(1)

        entry["provider_modified"] = content_json.get("modified", 0)

        domain_records = content_json.get("domain_records", {})

        log.info("resolveSubdomain: %d domain record(s) found at %s", len(domain_records), provider_address)

        record = domain_records.get(domain, {})
        if type(record) is str or type(record) is unicode:
            record = {"type": "A", "value": record}

        if record:
            log.info("resolveSubdomain: %s -> %s:%s", domain, record.get("type"), record.get("value"))

        record_type = record.get("type")
        address = None
        if record_type == "A":
            address = record.get("value")
        elif record_type == "NS":
            # not implemented
            pass

        entry["address"] = address
        return entry

@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):

    __idnameResolver = None

    def idnameResolver(self):
        if not self.__idnameResolver:
            self.__idnameResolver = IDNameResolver(self, config.zeroid_resolver)
        return self.__idnameResolver

    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        self.idnameResolver().load()

    # Checks if it's a valid address
    def isAddress(self, address):
        return self.idnameResolver().isIDDomain(address) or super(SiteManagerPlugin, self).isAddress(address)

    # Return: True if the address is domain
    def isDomain(self, address):
        return self.idnameResolver().isIDDomain(address) or super(SiteManagerPlugin, self).isDomain(address)

    # Return or create site and start download site files
    # Return: Site or None if dns resolve failed
    def need(self, address, *args, **kwargs):
        log.info("need: domain: %s", address)
        if self.idnameResolver().isIDDomain(address):  # Its looks like a domain
            address_resolved = self.idnameResolver().resolveIDDomain(address)
            log.info("need: %s -> %s", address, address_resolved)
            if address_resolved:
                address = address_resolved
            else:
                return None

        return super(SiteManagerPlugin, self).need(address, *args, **kwargs)

    # Return: Site object or None if not found
    def get(self, address):
        if not self.loaded:  # Not loaded yet
            self.load()
        log.info("get: domain: %s", address)
        if self.idnameResolver().isIDDomain(address):  # Its looks like a domain
            address_resolved = self.idnameResolver().resolveIDDomain(address)
            log.info("get: %s -> %s", address, address_resolved)
            if address_resolved:  # Domain found
                site = self.sites.get(address_resolved)
                if site:
                    site_domain = site.settings.get("domain")
                    if site_domain != address:
                        site.settings["domain"] = address
            else:  # Domain not found
                site = self.sites.get(address)

        else:  # Access by site address
            site = super(SiteManagerPlugin, self).get(address)
        return site


@PluginManager.registerTo("UiRequest")
class UiRequestPlugin(object):

    def __init__(self, *args, **kwargs):
        from Site import SiteManager
        self.site_manager = SiteManager.site_manager
        super(UiRequestPlugin, self).__init__(*args, **kwargs)

    # Media request
    def actionSiteMedia(self, path, **kwargs):
        match = re.match("/media/(?P<address>[A-Za-z0-9-]+\.[A-Za-z0-9\.-]+)(?P<inner_path>/.*|$)", path)
        if match:  # Its a valid domain, resolve first
            domain = match.group("address")
            address = self.site_manager.idnameResolver().resolveIDDomain(domain)
            if address:
                path = "/media/" + address + match.group("inner_path")
        return super(UiRequestPlugin, self).actionSiteMedia(path, **kwargs)  # Get the wrapper frame output


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("IDName plugin")
        group.add_argument('--zeroid_resolver', help='ZeroNet site to resolve *.zeroid.bit domains', default="1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz", metavar="address")

        return super(ConfigPlugin, self).createArguments()
