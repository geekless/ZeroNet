import logging
import re
import time

from Config import config
from Plugin import PluginManager

allow_reload = False  # No reload supported

log = logging.getLogger("IDNamePlugin")


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):
    __site_zeroid = None
    __db_domains = None
    __db_domains_modified = None

    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        if not self.get(config.zeroid_resolver):
            self.need(config.zeroid_resolver)

    # Checks if it's a valid address
    def isAddress(self, address):
        return self.isIDDomain(address) or super(SiteManagerPlugin, self).isAddress(address)

    # Return: True if the address is domain
    def isDomain(self, address):
        return self.isIDDomain(address) or super(SiteManagerPlugin, self).isDomain(address)

    # Return: True if the address is .zeroid domain
    def isIDDomain(self, address):
        return re.match("(.*?)([A-Za-z0-9_-]+\.zeroid)$", address)

    def getDataFileList(self):
        return filter(
            lambda x: re.match("data/.*\.json$", x),
            self.__site_zeroid.content_manager.contents.get("content.json", {}).get("files", {}).keys()
        )

    def resolveDomainFromFile(self, domain, file_name, allow_recursion = True):
        log.info("resolveDomainFromFile: %s" % file_name)
        self.__site_zeroid.needFile(file_name, priority=10)

        r = re.search("(.*?)([A-Za-z0-9_-]+)\.zeroid$", domain)
        subdomain = r.group(1)
        user_id = r.group(2)

        data = self.__site_zeroid.storage.loadJson(file_name)
        certs  = data.get("users", data.get("certs"))
        if not certs:
            return None

        cert = certs.get(user_id)
        if not cert:
            return None

        if cert.startswith("@") and allow_recursion:
            r = cert[1:].split(',')
            cert_file_name = "data/certs_%s.json" % r[0]
            return self.resolveDomainFromFile(domain, cert_file_name, allow_recursion = False)

        r = cert.split(',')
        return r[1]

    def resolveDomainNoCache(self, domain):
        log.info(self.getDataFileList())

        for data_file_name in self.getDataFileList():
            r = self.resolveDomainFromFile(domain, data_file_name)
            if r:
                return r
        return None

    # Resolve domain
    # Return: The address or None
    def resolveIDDomain(self, domain):
        domain = domain.lower()
        if not self.__site_zeroid:
            self.__site_zeroid = self.need(config.zeroid_resolver)

        site_zeroid_modified = self.__site_zeroid.content_manager.contents.get("content.json", {}).get("modified", 0)
        if not self.__db_domains or self.__db_domains_modified != site_zeroid_modified:
            self.__db_domains = {}
            self.__db_domains_modified = site_zeroid_modified

        if not self.__db_domains.has_key(domain):
            self.__db_domains[domain] = self.resolveDomainNoCache(domain)
        return self.__db_domains.get(domain)

    # Return or create site and start download site files
    # Return: Site or None if dns resolve failed
    def need(self, address, *args, **kwargs):
        log.info("need: domain: %s" % address)
        if self.isIDDomain(address):  # Its looks like a domain
            address_resolved = self.resolveIDDomain(address)
            log.info("need: address_resolved: %s", address_resolved)
            if address_resolved:
                address = address_resolved
            else:
                return None

        return super(SiteManagerPlugin, self).need(address, *args, **kwargs)

    # Return: Site object or None if not found
    def get(self, address):
        if not self.loaded:  # Not loaded yet
            self.load()
        log.info("get: domain: %s" % address)
        if self.isIDDomain(address):  # Its looks like a domain
            address_resolved = self.resolveIDDomain(address)
            log.info("get: address_resolved: %s", address_resolved)
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
            address = self.site_manager.resolveIDDomain(domain)
            if address:
                path = "/media/" + address + match.group("inner_path")
        return super(UiRequestPlugin, self).actionSiteMedia(path, **kwargs)  # Get the wrapper frame output


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("IDName plugin")
        group.add_argument('--zeroid_resolver', help='ZeroNet site to resolve *.zeroid.bit domains', default="1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz", metavar="address")

        return super(ConfigPlugin, self).createArguments()
