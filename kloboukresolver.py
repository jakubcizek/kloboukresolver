# K behu je treba knihovna dnspython:
# https://dnspython.readthedocs.io/en/latest/installation.html
# Pro overovani DNSSEC (parametr --dnssec) navic knihovna cryptography:
# pip install "dnspython[dnssec]"

# TENTO KOD VZNIKL JEN ZA UCELEM RYCHLE PREZENTACE AUTORITATIVNIHO DNS PREKLADU
# 1) Je to bastl!
# 2) Psal jsem ho bez hlubsi znalosti knihovny dnspython
# 3) Tomu odpovidaji nektere postupy, ktere by slo resit cisteji a lepe
# 4) V nekterych fazich napriklad opoustim parser knihovny dnspython a pracuji se surovym textem
# 5) Kod neimplementuje vsechny moznosti, neni osetreny na vsechny chyby 

import random
import base64
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.exception
import dns.dnssec
import dns.rdataclass
import dns.rrset
import sys
import time

# 13 vychozich root serveru
root_servers = [
    {
        "ip":"198.41.0.4",
        "op": "Verisign, Inc."
    },
    {
        "ip":"170.247.170.2",
        "op": "Information Sciences Institute"
    },
    {
        "ip":"192.33.4.12",
        "op": "Cogent Communications"
    },
    {
        "ip":"199.7.91.13",
        "op": "University of Maryland"
    },
    {
        "ip":"192.203.230.10",
        "op": "NASA Ames Research Center"
    },
    {
        "ip":"192.5.5.241",
        "op": "Internet Systems Consortium, Inc."
    },
    {
        "ip":"192.112.36.4",
        "op": "Defense Information Systems Agency"
    },
    {
        "ip":"198.97.190.53",
        "op": "U.S. Army Research Lab"
    },
    {
        "ip":"192.36.148.17",
        "op": "Netnod"
    },
    {
        "ip":"192.58.128.30",
        "op": "Verisign, Inc."
    },
    {
        "ip":"193.0.14.129",
        "op": "RIPE NCC"
    },
    {
        "ip":"199.7.83.42",
        "op": "ICANN"
    },
    {
        "ip":"202.12.27.33",
        "op": "WIDE Project"
    }
]

# Kotva duvery (trust anchor) pro DNSSEC
# Otisky (zaznamy DS) korenovych klicu KSK, kterym verime "natvrdo"
# Vsechno ostatni v DNSSEC se overuje postupne od nich
# Zdroj: https://data.iana.org/root-anchors/root-anchors.xml
# V roce 2026 probiha vymena korenoveho klice, a tak jsou zde oba
# Format: cislo klice (key tag), algoritmus (8 = RSASHA256), typ otisku (2 = SHA-256), otisk
trust_anchors = [
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",  # KSK-2017
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"   # KSK-2024
]

# Terminalove barvicky
class color:
   PURPLE = "\033[95m"
   CYAN = "\033[96m"
   DARKCYAN = "\033[36m"
   BLUE = "\033[94m"
   GREEN = "\033[92m"
   YELLOW = "\033[93m"
   RED = "\033[91m"
   BOLD = "\033[1m"
   UNDERLINE = "\033[4m"
   END = "\033[0m"


# Trida pro preklad
class KloboukResolver:
    # Konstruktor
    def __init__(self, domain, verbose=0, dnssec=False):
        self.domain = domain
        self.verbose = verbose
        # Zapnuti overovani DNSSEC
        self.dnssec = dnssec
        self.tabelator = " "
        self.tabsize = 5
        # Kolik sekund nejvyse cekam na odpoved serveru
        self.timeout = 3
        # Kolikrat se smi __resolve zavolat sama v sobe (ochrana proti zacykleni)
        self.max_depth = 10

    # Reset promennych pro statistiku a tabelovani/cislovani
    def reset(self):
        self.step = 0
        self.stats_query_counter = 0
        self.stats_query_nameservers = []
        # Vysledek overeni DNSSEC (prazdny = zatim nic neovereno)
        self.dnssec_status = ""

    # Verejna metoda pro zahajeni prekladu
    def resolve(self, domain=""):
        if domain == "":
            domain = self.domain

        # Vycisteni promennych pri dalsim pouziti metody
        self.reset()

        # Zavolani vnitrni/privatni metody pro dohledani IP
        # spolecne s merenim casu, jak dlouho to trva
        start = time.time()
        ip = self.__resolve(domain)
        end = time.time()

        # Slovnik se statistikou
        stats = {
            "query_counter": self.stats_query_counter,
            "query_nameservers": self.stats_query_nameservers,
            "time_start": start,
            "time_end": end,
            "dnssec_status": self.dnssec_status
        }
    
        # Vracim pole s IP a slovnik se statistikou
        return ip, stats

    # Privatni metoda pro odeslani jednoho DNS dotazu
    # Nevolat zvenci
    def __query(self, name, rdtype, nameserver):
        # Vytvoreni dotazu
        # Knihovna dnspython standardne nastavuje flag RD (Recursion Desired),
        # cimz server zada, aby cely preklad udelal za nas.
        # My ale strom prochazime sami, a tak flag vypneme pomoci flags=0
        # Pri overovani DNSSEC navic nastavim flag DO (DNSSEC OK),
        # aby server k zaznamum pribalil i jejich podpisy (RRSIG).
        # Podpisy jsou velke, a tak serveru reknu, ze zvladnu odpoved az 1232 bajtu
        if self.dnssec:
            query = dns.message.make_query(name, rdtype, flags=0, want_dnssec=True, payload=1232)
        else:
            query = dns.message.make_query(name, rdtype, flags=0)

        # Odeslani dotazu pres UDP s casovym limitem
        # Pokud se odpoved do UDP paketu nevejde, server nastavi flag TC (Truncated)
        # a knihovna pak dotaz automaticky zopakuje pres TCP
        response, used_tcp = dns.query.udp_with_fallback(query, nameserver, timeout=self.timeout)

        if used_tcp:
            protocol = "TCP"
        else:
            protocol = "UDP"

        # Statistika
        self.stats_query_counter += 1
        self.stats_query_nameservers.append(nameserver.ljust(20, " ") + f"(vyhledání {dns.rdatatype.to_text(rdtype)} záznamu pro doménu {name.to_text()} přes {protocol})")

        # Pokud jsem spustil program s parametrem --ukecany
        # vypise se pro kontrolu cela RAW odpoved v textovem formatu DNS
        # Viz https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
        if self.verbose == 1:
            print("*** ODPOVĚĎ DNS ***")
            print(str(response))
            print("*******************")

        return response

    # ************* POMOCNE METODY PRO DNSSEC *************

    # Vypis radku tykajiciho se DNSSEC, odsazeny podle aktualniho kroku
    def __dnssec_print(self, text):
        tab = self.tabelator * self.tabsize * self.step
        print(f"{tab}{(len(str(self.step))+2) * ' '}{color.CYAN}[DNSSEC]{color.END} {text}")

    # Ulozeni vysledku overeni DNSSEC
    # Celkovy vysledek je vzdy ten nejhorsi, ktery behem prekladu nastal
    # (napr. kdyz se pres CNAME dostanu z podepsane domeny do nepodepsane)
    def __dnssec_result(self, status):
        order = ["", "SECURE", "INSECURE", "BOGUS"]
        if order.index(status) > order.index(self.dnssec_status):
            self.dnssec_status = status

    # Barevny text s vysledkem overeni DNSSEC
    def __status_text(self, status):
        if status == "SECURE":
            return f"{color.GREEN}SECURE{color.END}"
        elif status == "INSECURE":
            return f"{color.YELLOW}INSECURE{color.END}"
        elif status == "BOGUS":
            return f"{color.RED}BOGUS{color.END}"
        else:
            return "NEOVĚŘENO"

    # Najde v sekci odpovedi zaznamy daneho typu a k nim jejich podpis RRSIG
    # Pokud tam nejsou, vrati None
    def __find_rrset(self, response, section, name, rdtype):
        rrset = response.get_rrset(section, name, dns.rdataclass.IN, rdtype)
        rrsig = response.get_rrset(section, name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rdtype)
        return rrset, rrsig

    # Overeni podpisu RRSIG nad sadou zaznamu
    # 'keys' je sada klicu DNSKEY zony 'zone', ktera mela zaznamy podepsat
    # Vraci True, pokud je podpis platny
    def __dnssec_verify(self, rrset, rrsig, zone, keys):
        record = f"{rrset.name.to_text()} {dns.rdatatype.to_text(rrset.rdtype)}"

        if rrsig is None:
            self.__dnssec_print(f"{color.RED}Záznamy {record} nemají podpis RRSIG{color.END}")
            return False

        # Knihovna sama najde klic podle cisla (key tag) v podpisu,
        # spocita kryptograficky podpis a zkontroluje i jeho platnost v case
        try:
            dns.dnssec.validate(rrset, rrsig, {zone: keys})
        except dns.exception.DNSException as e:
            self.__dnssec_print(f"{color.RED}Podpis záznamů {record} je NEPLATNÝ ({e}){color.END}")
            return False

        # Pro vypis zjistim, kterymi z overenych klicu byly zaznamy podepsany
        key_tags = [dns.dnssec.key_id(key) for key in keys]
        signed_by = ", ".join(str(sig.key_tag) for sig in rrsig if sig.key_tag in key_tags)
        self.__dnssec_print(f"{color.GREEN}Podpis záznamů {record} klíčem {signed_by} zóny {zone.to_text()} je platný{color.END}")
        return True

    # Overeni klicu (DNSKEY) zony
    # 1) Stahnu ze serveru zony sadu jejich klicu DNSKEY
    # 2) Najdu klic KSK, jehoz otisk odpovida nekteremu zaznamu DS
    #    (DS je ulozeny v nadrazene zone, u korene ho nahrazuje nase kotva duvery)
    # 3) Overim, ze tento KSK podepsal celou sadu klicu, a tedy i klic ZSK,
    #    kterym jsou podepsane vsechny ostatni zaznamy v zone
    # Vraci overenou sadu klicu, nebo None, pokud overeni selhalo
    def __dnssec_zone_keys(self, zone, nameserver, ds_rrset):
        self.__dnssec_print(f"Ptám se {color.YELLOW}{nameserver}{color.END} na klíče (DNSKEY) zóny {color.YELLOW}{zone.to_text()}{color.END}")
        response = self.__query(zone, dns.rdatatype.DNSKEY, nameserver)
        dnskeys, dnskeys_sig = self.__find_rrset(response, response.answer, zone, dns.rdatatype.DNSKEY)

        if dnskeys is None:
            self.__dnssec_print(f"{color.RED}Server nevrátil žádné klíče DNSKEY{color.END}")
            return None

        # Vypis klicu
        # Flags 257 = KSK (Key Signing Key) podepisuje jen sadu klicu
        # Flags 256 = ZSK (Zone Signing Key) podepisuje ostatni zaznamy zony
        for key in dnskeys:
            if key.flags == 257:
                key_type = "KSK"
            else:
                key_type = "ZSK"
            self.__dnssec_print(f"Klíč {dns.dnssec.key_id(key)} ({key_type}, {dns.dnssec.algorithm_to_text(key.algorithm)})")

        # Hledam klice, jejichz otisk (hash) se shoduje s nekterym DS zaznamem
        # Muze jich byt i vic, napr. behem vymeny klice (key rollover),
        # kdy je v DS otisk stareho i noveho klice
        ksk_list = []
        for ds in ds_rrset:
            for key in dnskeys:
                if dns.dnssec.key_id(key) == ds.key_tag and key.algorithm == ds.algorithm:
                    # Spocitam otisk klice stejnym algoritmem, jaky pouziva DS
                    try:
                        computed_ds = dns.dnssec.make_ds(zone, key, ds.digest_type, validating=True)
                    except dns.exception.DNSException:
                        continue
                    if computed_ds == ds:
                        ksk_list.append(key)
                        self.__dnssec_print(f"{color.GREEN}Otisk klíče {dns.dnssec.key_id(key)} odpovídá záznamu DS{color.END}")

        if len(ksk_list) == 0:
            self.__dnssec_print(f"{color.RED}Žádný klíč neodpovídá otisku DS, řetěz důvěry je přerušený{color.END}")
            return None

        # Sadu klicu musi podepsat nektery z techto overenych klicu,
        # a tak pro overeni podpisu pouziji jen je
        ksk_rrset = dns.rrset.from_rdata_list(zone, dnskeys.ttl, ksk_list)
        if not self.__dnssec_verify(dnskeys, dnskeys_sig, zone, ksk_rrset):
            return None

        return dnskeys

    # ************* DUKAZY NEEXISTENCE (NSEC / NSEC3) *************
    # Server nemuze podepsat odpoved "nic tu neni", protoze podpisy se vytvari predem
    # a neexistujicich jmen je nekonecne mnoho. Misto toho ma zona predem podepsany
    # seznam vsech existujicich jmen serazeny podle abecedy. Kazdy zaznam NSEC rika:
    # "za jmenem X nasleduje jmeno Y a mezi nimi nic neni" a "X ma tyto typy zaznamu".
    # NSEC3 dela totez, jen misto jmen pouziva jejich hashe, aby nesel snadno
    # stahnout seznam vsech domen v zone (tzv. zone walking).

    # Seznam typu zaznamu, ktere podle NSEC/NSEC3 u domeny existuji
    # Typy jsou ulozene jako bitova mapa rozdelena do "oken" po 256 typech:
    # kazdy bit odpovida jednomu cislu typu (1 = A, 2 = NS, 5 = CNAME, 43 = DS, ...)
    def __nsec_types(self, rdata):
        types = []
        for window, bitmap in rdata.windows:
            for i, byte in enumerate(bitmap):
                for bit in range(8):
                    if byte & (0x80 >> bit):
                        types.append(window * 256 + i * 8 + bit)
        return types

    # Text se seznamem typu pro vypis, napr. "NS, DS, RRSIG"
    def __types_text(self, types):
        return ", ".join(dns.rdatatype.to_text(t) for t in types)

    # Lezi 'value' mezi 'owner' a 'next'? Tedy "prekryva" ho zaznam NSEC/NSEC3?
    # Seznam jmen v zone je kruhovy: posledni zaznam ukazuje zpet na prvni,
    # a tak u posledniho zaznamu (owner > next) plati opacna podminka
    # Funguje pro jmena domen (NSEC) i pro hashe (NSEC3)
    def __covers(self, owner, next_name, value):
        if owner < next_name:
            return owner < value < next_name
        else:
            return value > owner or value < next_name

    # NSEC3 hash jmena domeny (zakodovany do textu stejne jako v nazvech zaznamu NSEC3)
    def __nsec3_hash(self, name, params):
        return dns.dnssec.nsec3_hash(name, params.salt, params.iterations, params.algorithm)

    # Najde NSEC3 zaznam, jehoz nazev je presne dany hash (= domena s timto hashem existuje)
    def __nsec3_match(self, nsec3_list, hashed):
        for nsec3 in nsec3_list:
            if nsec3.name.labels[0].decode().upper() == hashed:
                return nsec3
        return None

    # Najde NSEC3 zaznam, ktery dany hash "prekryva" (= domena s timto hashem neexistuje)
    # Nazev zaznamu obsahuje hash jako text, dalsi hash je v datech jako bajty,
    # a tak ho prevedu na text stejnym kodovanim (base32hex)
    def __nsec3_cover(self, nsec3_list, hashed):
        for nsec3 in nsec3_list:
            owner_hash = nsec3.name.labels[0].decode().upper()
            next_hash = base64.b32hexencode(nsec3[0].next).decode().upper()
            if self.__covers(owner_hash, next_hash, hashed):
                return nsec3
        return None

    # Overeni dukazu neexistence
    # name   = domena, na kterou jsem se ptal
    # rdtype = typ zaznamu, ktery neexistuje (None = neexistuje cela domena, tedy NXDOMAIN)
    # zone, keys = zona, ktera odpoved podepsala, a jeji overene klice
    # Vraci True, pokud je dukaz platny
    def __dnssec_denial(self, response, name, rdtype, zone, keys):
        if rdtype is None:
            self.__dnssec_print(f"Ověřím důkaz, že doména {color.YELLOW}{name.to_text()}{color.END} neexistuje")
        else:
            self.__dnssec_print(f"Ověřím důkaz, že doména {color.YELLOW}{name.to_text()}{color.END} nemá záznam {dns.rdatatype.to_text(rdtype)}")

        # Vyberu ze sekce AUTHORITY vsechny zaznamy NSEC/NSEC3 a overim jejich podpisy
        nsec_list = []
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC or rrset.rdtype == dns.rdatatype.NSEC3:
                rrsig = response.get_rrset(response.authority, rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype)
                if not self.__dnssec_verify(rrset, rrsig, zone, keys):
                    return False
                nsec_list.append(rrset)

        if len(nsec_list) == 0:
            self.__dnssec_print(f"{color.RED}Odpověď neobsahuje žádné záznamy NSEC ani NSEC3{color.END}")
            return False

        if nsec_list[0].rdtype == dns.rdatatype.NSEC:
            return self.__dnssec_denial_nsec(nsec_list, name, rdtype)
        else:
            return self.__dnssec_denial_nsec3(nsec_list, name, rdtype, zone)

    # Dukaz neexistence pomoci NSEC (jmena jsou v zaznamech videt primo)
    def __dnssec_denial_nsec(self, nsec_list, name, rdtype):
        # Domena existuje, jen nema hledany typ zaznamu (NODATA):
        # Musi existovat NSEC presne pro tuto domenu a v jeho seznamu typu nesmi byt hledany typ
        if rdtype is not None:
            for nsec in nsec_list:
                if nsec.name == name:
                    types = self.__nsec_types(nsec[0])
                    self.__dnssec_print(f"NSEC říká, že {name.to_text()} má jen tyto typy záznamů: {self.__types_text(types)}")
                    return self.__dnssec_check_types(types, rdtype)
            self.__dnssec_print(f"{color.RED}Chybí záznam NSEC pro doménu {name.to_text()}{color.END}")
            return False

        # Domena vubec neexistuje (NXDOMAIN):
        # 1) Nektery NSEC musi jmeno "prekryvat", tedy jmeno lezi mezi dvema existujicimi jmeny
        covering = None
        for nsec in nsec_list:
            if self.__covers(nsec.name, nsec[0].next, name):
                covering = nsec
        if covering is None:
            self.__dnssec_print(f"{color.RED}Žádný NSEC nepokrývá jméno {name.to_text()}{color.END}")
            return False
        self.__dnssec_print(f"NSEC říká, že mezi {covering.name.to_text()} a {covering[0].next.to_text()} nic není, takže {name.to_text()} neexistuje")

        # 2) Nesmi existovat ani wildcard *.<nejblizsi existujici predek>,
        #    jinak by server misto NXDOMAIN odpovedel zaznamy z wildcardu
        #    Nejblizsi existujici predek (closest encloser) je nejdelsi spolecna cast
        #    hledaneho jmena a jmen v prekryvajicim NSEC
        common_owner = name.fullcompare(covering.name)[2]
        common_next = name.fullcompare(covering[0].next)[2]
        encloser = name.split(max(common_owner, common_next))[1]
        wildcard = dns.name.Name((b"*",) + encloser.labels)
        for nsec in nsec_list:
            if self.__covers(nsec.name, nsec[0].next, wildcard):
                self.__dnssec_print(f"{color.GREEN}Neexistuje ani wildcard {wildcard.to_text()}, doména {name.to_text()} opravdu neexistuje{color.END}")
                return True
        self.__dnssec_print(f"{color.RED}Chybí důkaz, že neexistuje wildcard {wildcard.to_text()}{color.END}")
        return False

    # Dukaz neexistence pomoci NSEC3 (misto jmen jsou v zaznamech jejich hashe)
    def __dnssec_denial_nsec3(self, nsec3_list, name, rdtype, zone):
        # Parametry hashovani (algoritmus, pocet iteraci a sul) jsou u vsech NSEC3 v zone stejne
        params = nsec3_list[0][0]
        if len(params.salt) > 0:
            salt = params.salt.hex()
        else:
            salt = "žádná"
        self.__dnssec_print(f"Zóna používá NSEC3, jména jsou zahashovaná (iterací: {params.iterations}, sůl: {salt})")

        hashed = self.__nsec3_hash(name, params)
        match = self.__nsec3_match(nsec3_list, hashed)

        # Domena existuje, jen nema hledany typ zaznamu (NODATA):
        # Existuje NSEC3 presne s hashem teto domeny, zkontroluji v nem seznam typu
        if match is not None:
            if rdtype is None:
                self.__dnssec_print(f"{color.RED}NSEC3 tvrdí, že doména {name.to_text()} existuje, server ale tvrdí opak{color.END}")
                return False
            types = self.__nsec_types(match[0])
            self.__dnssec_print(f"NSEC3 s hashem {hashed} říká, že {name.to_text()} má jen tyto typy záznamů: {self.__types_text(types)}")
            return self.__dnssec_check_types(types, rdtype)

        # Jinak musim dokazat, ze domena neexistuje (tzv. closest encloser proof):
        # 1) Najdu nejblizsiho existujiciho predka (closest encloser), ktery ma vlastni NSEC3
        # 2) Jmeno o jednu uroven delsi smerem k hledane domene (next closer) musi
        #    byt "prekryte" nejakym NSEC3, tedy neexistuje
        closest_encloser = None
        next_closer = name
        # Postupne zkracuji jmeno o prvni cast, dokud nevylezu ze zony
        candidate = name.parent()
        while candidate.is_subdomain(zone):
            if self.__nsec3_match(nsec3_list, self.__nsec3_hash(candidate, params)) is not None:
                closest_encloser = candidate
                break
            next_closer = candidate
            if candidate == dns.name.root:
                break
            candidate = candidate.parent()

        if closest_encloser is None:
            self.__dnssec_print(f"{color.RED}Chybí NSEC3 pro nejbližší existující nadřazenou doménu{color.END}")
            return False
        self.__dnssec_print(f"Nejbližší existující nadřazená doména je {closest_encloser.to_text()}")

        next_closer_hash = self.__nsec3_hash(next_closer, params)
        covering = self.__nsec3_cover(nsec3_list, next_closer_hash)
        if covering is None:
            self.__dnssec_print(f"{color.RED}Žádný NSEC3 nepokrývá hash {next_closer_hash} jména {next_closer.to_text()}{color.END}")
            return False
        next_hash = base64.b32hexencode(covering[0].next).decode().upper()
        self.__dnssec_print(f"Hash {next_closer_hash} jména {next_closer.to_text()} leží mezi {covering.name.labels[0].decode().upper()} a {next_hash}, takže neexistuje")

        # U chybejiciho DS muze zona pouzivat tzv. opt-out: nepodepsane delegace
        # se do retezu NSEC3 vubec nezapisuji (setri to misto u velkych zon jako com.)
        # Prekryvajici NSEC3 pak musi mit nastaveny priznak opt-out (bit 1 v polozce flags)
        if rdtype == dns.rdatatype.DS:
            if covering[0].flags & 1:
                self.__dnssec_print(f"{color.GREEN}NSEC3 má příznak opt-out, delegace {name.to_text()} tedy není podepsaná{color.END}")
                return True
            self.__dnssec_print(f"{color.RED}NSEC3 nemá příznak opt-out, důkaz neplatí{color.END}")
            return False

        if rdtype is not None:
            self.__dnssec_print(f"{color.RED}Chybí NSEC3 pro doménu {name.to_text()}{color.END}")
            return False

        # 3) U NXDOMAIN nesmi existovat ani wildcard *.<closest encloser>
        wildcard = dns.name.Name((b"*",) + closest_encloser.labels)
        if self.__nsec3_cover(nsec3_list, self.__nsec3_hash(wildcard, params)) is None:
            self.__dnssec_print(f"{color.RED}Chybí důkaz, že neexistuje wildcard {wildcard.to_text()}{color.END}")
            return False
        self.__dnssec_print(f"{color.GREEN}Neexistuje ani wildcard {wildcard.to_text()}, doména {name.to_text()} opravdu neexistuje{color.END}")
        return True

    # Kontrola seznamu typu z NSEC/NSEC3 u odpovedi NODATA
    def __dnssec_check_types(self, types, rdtype):
        # Hledany typ v seznamu byt nesmi, a nesmi tam byt ani CNAME
        # (jinak by server misto prazdne odpovedi musel vratit alias)
        if rdtype in types or dns.rdatatype.CNAME in types:
            self.__dnssec_print(f"{color.RED}Záznam {dns.rdatatype.to_text(rdtype)} ve skutečnosti existuje, důkaz neplatí{color.END}")
            return False
        # U DS musi NSEC pochazet z nadrazene zony
        # Kdyby obsahoval SOA, je to NSEC z vrcholu podrizene zony, a ten o DS nic nerika
        if rdtype == dns.rdatatype.DS and dns.rdatatype.SOA in types:
            self.__dnssec_print(f"{color.RED}NSEC pochází z podřízené zóny, o záznamu DS nic neříká{color.END}")
            return False
        self.__dnssec_print(f"{color.GREEN}Záznam {dns.rdatatype.to_text(rdtype)} opravdu neexistuje{color.END}")
        return True

    # Privatni metoda pro zahajeni prekladu
    # Nevolat zvenci
    # Parametr depth rika, kolikrat uz se tato metoda zavolala sama v sobe
    def __resolve(self, domain, depth=0):
        # Pole s vysledky, nalezenymi IP adresami
        ip = []

        # DNSSEC overuji jen pokud je zapnuty parametrem --dnssec
        # Promenna 'dnssec' se behem prekladu vypne, pokud zjistim,
        # ze zona neni podepsana (INSECURE) nebo overeni selhalo (BOGUS)
        dnssec = self.dnssec

        # Ochrana proti nekonecne rekurzi
        # (napr. dva nameservery, ktere na sebe navzajem odkazuji, nebo smycka CNAME zaznamu)
        if depth > self.max_depth:
            print(f"{color.RED}Příliš mnoho vnořených dotazů, vzdávám to{color.END}")
            return ip

        # Z textu vytvorim DNS objekt domeny
        # Knihovna si sama poradi s teckou na konci (zive.cz i zive.cz.)
        # a domeny s hacky a carkami prevede do tvaru xn--... (IDN)
        domain_name = dns.name.from_text(domain)

        # Volba nahodneho korenoveho nameserveru
        root_server = random.choice(root_servers)
        nameserver = root_server["ip"]
        operator = root_server["op"]
        nameserver_domain = ""

        # Vytvoreni prvniho textoveho odsazeni
        # a vypsani uvitaci zpravy
        self.step += 1
        tab = self.tabelator * self.tabsize * self.step
        print("")
        print(f"{color.BOLD}{tab}{self.step}. Budu hledat IP adresu pro {color.YELLOW}{domain_name.to_unicode(omit_final_dot=True)}{color.END}")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Na začátku znám pouze 13 IP adres nejvyšších kořenových serverů systému DNS (root-servers.org)")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Volím náhodný kořenový DNS server: {color.YELLOW}{nameserver}{color.END}")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Operátor: {color.YELLOW}{operator}{color.END}")
        # U vnoreneho hledani (adresa nameserveru, cil aliasu CNAME) vysvetlim,
        # proc zacinam znovu od korene, prestoze jsem tam pred chvili byl
        if depth > 0:
            print(f"{tab}{(len(str(self.step))+2) * ' '}Nic si nepamatuji (nemám cache), a tak začínám znovu od kořene")
        print("")

        # DNSSEC: Retez duvery zacina u korene
        # Klice korenove zony overim proti kotve duvery, kterou mam ulozenou v programu
        # Promenna 'zone' je vzdy posledni overena zona a 'zone_keys' jeji overene klice
        if dnssec:
            zone = dns.name.root
            anchors = dns.rrset.from_text_list(zone, 0, "IN", "DS", trust_anchors)
            anchor_tags = ", ".join(str(anchor.key_tag) for anchor in anchors)
            
            self.__dnssec_print(f"Pozor, aktivoval jsi ověřování pravosti pomocí DNSSEC, takže to bude fičák!")
            self.__dnssec_print(f"Na začátku znám tyto otisky kořenových klíčů: {anchor_tags}")
            zone_keys = self.__dnssec_zone_keys(zone, nameserver, anchors)
            if zone_keys is None:
                self.__dnssec_result("BOGUS")
                dnssec = False
            print("")

        # Priprava domeny
        # DNS strom prochazim od korene, takze pro www.zive.cz
        # potrebuji postupne domeny: cz., zive.cz., www.zive.cz.
        # Metoda parent() z domeny vzdy odebere prvni cast:
        # www.zive.cz. -> zive.cz. -> cz. -> . (koren)
        # Kazdou domenu vlozim na zacatek seznamu, takze budou serazene od korene
        subdomains = []
        name = domain_name
        while name != dns.name.root:
            subdomains.insert(0, name)
            name = name.parent()

        # Projdu pole subdomen
        for current_subdomain in subdomains:

            # Pomocne promenne pro cislovani dotazu a odsazeni
            # pro kaskadovite vypsani vysledku
            self.step += 1
            tab = self.tabelator * self.tabsize * self.step

            # Ptam se serveru 'nameserver', jestli nema zaznamy typu NS pro domenu 'current_domain'
            print(f"{color.BOLD}{tab}{self.step}. Ptám se {color.YELLOW}{nameserver}{color.END}{color.BOLD}, kdo má na seznamu {color.YELLOW}{current_subdomain.to_text()}{color.END} ")
            response = self.__query(current_subdomain, dns.rdatatype.NS, nameserver)

            # Zapamatuji si server nadrazene zony, nameserver se muze v nasledujicich krocich zmenit
            parent_nameserver = nameserver

            # Pokud server odpovi kodem NXDOMAIN (Non-Existent Domain),
            # domena neexistuje a nema smysl se ptat dal
            if response.rcode() == dns.rcode.NXDOMAIN:
                print(f"{tab}{(len(str(self.step))+2) * ' '}{color.RED}Doména {current_subdomain.to_text()} neexistuje (NXDOMAIN){color.END}")
                # DNSSEC: Neexistenci domeny musi server dokazat podepsanymi zaznamy NSEC/NSEC3
                if dnssec:
                    if self.__dnssec_denial(response, current_subdomain, None, zone, zone_keys):
                        self.__dnssec_result("SECURE")
                    else:
                        self.__dnssec_result("BOGUS")
                print("")
                return ip

            # Zkusim dohledat prvni A zaznam s IP adresou v sekci ADDITIONAL
            # Pouziji prvni nalezeny
            for additional in response.additional:
                if additional.rdtype == dns.rdatatype.A:
                    print(f"{tab}{(len(str(self.step))+2) * ' '}Skvělé, odpověď obsahuje záznam A s IP adresou")
                    # Toto neni uplne ciste reseni
                    nameserver = additional[0].to_text()
                    nameserver_domain = additional.to_text().split(" ")[0]
                    print(f"{tab}{(len(str(self.step))+2) * ' '}Doména {color.YELLOW}{current_subdomain.to_text()}{color.END} je na seznamu {color.YELLOW}{nameserver} ({nameserver_domain}){color.END}")
                    print("")
                    break

            # Pokud jsem zadny A zaznam s IP adresou nameserveru nenasel....
            # Pozor, tato vetev 'else' patri k cyklu 'for', ne k podmince 'if'!
            # Provede se jen tehdy, kdyz cyklus dobehne az do konce a neukonci ho 'break'
            # (tedy i kdyz je sekce ADDITIONAL uplne prazdna, nebo obsahuje jen IPv6 zaznamy AAAA)
            else:
                # Zkusim najit v sekci AUTHORITY alespon domeny nameserveru
                # Pouziji prvni nalezenou a rekurzivnim volanim teto funkce pro ni dohledam IP
                if len(response.authority) > 0:
                    err = True
                    for authority in response.authority:
                        if authority.rdtype == dns.rdatatype.NS:
                            # Toto neni uplne ciste reseni
                            nameserver_domain = authority[0].to_text()
                            nameserver_line = authority.to_text().split("\n")[0]
                            print(f"{tab}{(len(str(self.step))+2) * ' '}Ale ne, znám jen doménu: {nameserver_line}")
                            print(f"{tab}{(len(str(self.step))+2) * ' '}Doména {color.YELLOW}{current_subdomain.to_text()}{color.END} je na seznamu {color.YELLOW}{nameserver_domain}{color.END}")
                            # Pomocne hledani IP adresy nameserveru, opet celou cestou od korene
                            # (nic si nepamatuji, a tak zacinam znovu od kotvy duvery)
                            # DNSSEC overim i tady, vysledek si ale ulozim zvlast, protoze
                            # na overeni hlavni domeny vliv nema: pravost odpovedi se pozna
                            # podle podpisu zony, ne podle toho, od ktereho serveru prisla
                            main_status = self.dnssec_status
                            self.dnssec_status = ""
                            nameserver_ip = self.__resolve(nameserver_domain, depth + 1)
                            nameserver_status = self.dnssec_status
                            self.dnssec_status = main_status

                            if self.dnssec:
                                self.__dnssec_print(f"Výsledek pro adresu nameserveru {color.YELLOW}{nameserver_domain}{color.END}: {self.__status_text(nameserver_status)}")
                                self.__dnssec_print(f"Na ověření domény {color.YELLOW}{current_subdomain.to_text()}{color.END} to vliv nemá: pravost odpovědí se pozná podle podpisů zóny,")
                                self.__dnssec_print("ne podle toho, od kterého serveru přišly")
                                print("")

                            # Rekurzivni hledani nemusi uspet a vratit prazdne pole
                            if len(nameserver_ip) > 0:
                                nameserver = nameserver_ip[0]
                                err = False
                            break
                    if err:
                        print(f"{tab}{(len(str(self.step))+2) * ' '}Žádná další odpověď, použiji poslední známý server")
                        print("")

                # Pokud je sekce AUTHORITY prazdna, prohledam sekci ANSWER
                elif len(response.answer) > 0:
                    err = True
                    for answer in response.answer:
                        if answer.rdtype == dns.rdatatype.NS:
                            for line in answer:
                                # Pokud je domena nameserveru v odpovedi stejna jako posledni znama domena nameserveru,
                                # tuto subdomenu spravuje stejny nameserver jako tu predchozi, a tak pokracuji
                                if line.to_text() == nameserver_domain:
                                    print(f"{tab}{(len(str(self.step))+2) * ' '}Doména {color.YELLOW}{current_subdomain.to_text()}{color.END} je na stejném seznamu")
                                    print("")  
                                    err = False 
                                    break 
                    if err:
                        print(f"{tab}{(len(str(self.step))+2) * ' '}Žádná další odpověď, použiji poslední známý server")
                        print("")

                # Tento program neni plne validni DNS dotazovac = nema implementovane zdaleka vsechny moznosti
                # Je jen rychle zbastleny pro zakladni demonstraci dohledani IP napric celym stromem u korektni domeny
                # Takze pokud jsem doposud nenasel IP nameserveru, proste pouziji ten posledni znamy
                # Muze to byt dano treba tim, ze se snazim dohledat domenu, ktera na seznamu proste neni = neexistuje
                else:
                    print(f"{tab}{(len(str(self.step))+2) * ' '}Žádná další odpověď, použiji poslední známý server")
                    print("")

            # DNSSEC: Pokud ma current_subdomain vlastni NS zaznamy, zacina zde nova zona (zone cut)
            # Musim proto overit retez duvery z nadrazene zony do teto nove zony
            if dnssec:
                ns_in_authority = response.get_rrset(response.authority, current_subdomain, dns.rdataclass.IN, dns.rdatatype.NS)
                ns_in_answer = response.get_rrset(response.answer, current_subdomain, dns.rdataclass.IN, dns.rdatatype.NS)

                if ns_in_authority is not None or ns_in_answer is not None:
                    self.__dnssec_print(f"Doména {color.YELLOW}{current_subdomain.to_text()}{color.END} je samostatná zóna, ověřím řetěz důvěry")

                    # Otisk klice podrizene zony (DS) je ulozeny v nadrazene zone
                    # Vetsinou prisel rovnou v odpovedi spolecne se zaznamy NS,
                    # jinak se na nej nadrazeneho serveru zeptam
                    ds, ds_sig = self.__find_rrset(response, response.authority, current_subdomain, dns.rdatatype.DS)
                    if ds is None:
                        self.__dnssec_print(f"Ptám se {color.YELLOW}{parent_nameserver}{color.END} na otisk klíče (DS) zóny {color.YELLOW}{current_subdomain.to_text()}{color.END}")
                        ds_response = self.__query(current_subdomain, dns.rdatatype.DS, parent_nameserver)
                        ds, ds_sig = self.__find_rrset(ds_response, ds_response.answer, current_subdomain, dns.rdatatype.DS)

                    # Bez DS neni zona podepsana a od tohoto mista uz nic overit nejde
                    # Nadrazena zona ale musi podepsanymi zaznamy NSEC/NSEC3 dokazat, ze DS opravdu nema
                    # Jinak by utocnik mohl DS z odpovedi jednoduse vymazat a vydavat podepsanou zonu za nepodepsanou
                    if ds is None:
                        self.__dnssec_print(f"{color.YELLOW}Zóna {current_subdomain.to_text()} nemá záznam DS{color.END}")
                        if self.__dnssec_denial(ds_response, current_subdomain, dns.rdatatype.DS, zone, zone_keys):
                            self.__dnssec_print(f"{color.YELLOW}Zóna {current_subdomain.to_text()} prokazatelně není podepsaná (INSECURE){color.END}")
                            self.__dnssec_result("INSECURE")
                        else:
                            self.__dnssec_result("BOGUS")
                        dnssec = False

                    # DS musi byt podepsany klicem nadrazene zony
                    elif not self.__dnssec_verify(ds, ds_sig, zone, zone_keys):
                        self.__dnssec_result("BOGUS")
                        dnssec = False

                    # A nakonec overim klice nove zony proti DS
                    else:
                        new_zone_keys = self.__dnssec_zone_keys(current_subdomain, nameserver, ds)
                        if new_zone_keys is None:
                            self.__dnssec_result("BOGUS")
                            dnssec = False
                        else:
                            zone = current_subdomain
                            zone_keys = new_zone_keys

                    print("")

        # Prosel jsem cely strom domeny
        # Nyni posledni znamy nameserver pouziji pro vyhledani IP adresy domeny
        self.step +=1
        tab = self.tabelator * self.tabsize * self.step
        print(f"{color.BOLD}{tab}{self.step}. Ptám se {color.YELLOW}{nameserver}{color.END}{color.BOLD}, jakou IP adresu má {color.YELLOW}{current_subdomain.to_text()}{color.END}")
        response = self.__query(current_subdomain, dns.rdatatype.A, nameserver)

        # Pokud je nameserver, ktereho se prave ptam na zaznam A, autoritativni,
        # odpoved musi obsahovat flag AA (Authoritative Answer). Je to tedy
        # takovy test, ze jsem prosel DNS strom opravdu ke spravnemu nameserveru
        if len(response.answer) > 0 and dns.flags.AA in response.flags:
            print(f"{tab}{(len(str(self.step))+2) * ' '}{color.GREEN}Odpověď obsahuje flag AA a je autoritativní{color.END}")

        # Domena muze mit vicero A zaznamu a tedy i vice IP adres,
        # vysledkem je tedy vzdy pole IP
        # Misto A zaznamu ale muze odpoved obsahovat CNAME = alias,
        # tedy informaci, ze domena je jen jinym jmenem pro uplne jinou domenu
        cname = ""
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.A:
                for ip_address in answer:
                    ip.append(str(ip_address))
                    print(f"{color.BOLD}{tab}{(len(str(self.step))+2) * ' '}IP: {color.GREEN}{str(ip_address)}{color.END}")
            elif answer.rdtype == dns.rdatatype.CNAME:
                cname = answer[0].to_text()
        print("")

        # DNSSEC: Posledni krok retezu duvery
        # Kazda sada zaznamu v odpovedi (A, pripadne CNAME) musi byt podepsana
        # klicem zony, kterou jsem overil jako posledni
        if dnssec:
            answer_valid = True
            answer_count = 0
            other_names = False
            for answer in response.answer:
                # Samotne podpisy RRSIG preskocim, overuji je spolecne se zaznamy
                if answer.rdtype == dns.rdatatype.RRSIG:
                    continue
                # Server muze k aliasu CNAME rovnou pribalit i zaznamy jeho cile
                # Cil ale muze patrit do uplne jine zony s jinymi klici,
                # a tak tyto zaznamy preskocim a cil pozdeji overim samostatne od korene
                if answer.name != current_subdomain:
                    other_names = True
                    continue
                answer_count += 1
                answer_sig = response.get_rrset(response.answer, answer.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, answer.rdtype)
                if not self.__dnssec_verify(answer, answer_sig, zone, zone_keys):
                    answer_valid = False

            # Prazdna odpoved: domena neexistuje (NXDOMAIN), nebo nema zaznam A (NODATA)
            # Obojí musi server dokazat podepsanymi zaznamy NSEC/NSEC3
            if answer_count == 0:
                if response.rcode() == dns.rcode.NXDOMAIN:
                    missing_type = None
                else:
                    missing_type = dns.rdatatype.A
                if self.__dnssec_denial(response, current_subdomain, missing_type, zone, zone_keys):
                    self.__dnssec_result("SECURE")
                else:
                    self.__dnssec_result("BOGUS")
            elif answer_valid:
                self.__dnssec_result("SECURE")
            else:
                self.__dnssec_result("BOGUS")

            # IP adresy cile aliasu jsem neoveril, a tak je zahodim
            # a cil aliasu dohledam a overim znovu celou cestou od korene
            if other_names and cname != "":
                self.__dnssec_print(f"Záznamy pro cíl aliasu {color.YELLOW}{cname}{color.END} ověřím samostatně od kořene")
                ip = []
            print("")

        # Pokud jsem nenasel zadnou IP, ale odpoved obsahovala CNAME,
        # musim cely preklad zopakovat od korene pro cilovou domenu aliasu
        if len(ip) == 0 and cname != "":
            print(f"{tab}{(len(str(self.step))+2) * ' '}Ale ne, {color.YELLOW}{current_subdomain.to_text()}{color.END} je jen alias (CNAME) pro {color.YELLOW}{cname}{color.END}")
            ip = self.__resolve(cname, depth + 1)

        # Pokud je pole s vysledky prazdne,
        # tento nameserver tuto domenu asi vubec nespravuje
        # Pravdepodobne jsem zadal nesmyslnou domenu?
        elif len(ip) == 0:
            print(f"{tab}{(len(str(self.step))+2) * ' '}{color.RED}Nenašel jsem žádnou IP adresu ;-({color.END}")
            print("")

        # Vrat pole IP adres
        return ip

# ************* ZACATEK PROGRAMU *************
if __name__ == "__main__":
    
    # Domenou je prvni parametr, ktery nezacina '--'
    # (parametry --ukecany a --dnssec tak mohou byt pred domenou i za ni)
    domain = ""
    for argument in sys.argv[1:]:
        if not argument.startswith("--"):
            domain = argument
            break

    # Napoveda pri spusteni bez domeny
    if domain == "":
        print("Pouziti: python3 resolver.py zive.cz")
        print("Pouziti: python3 resolver.py zive.cz --ukecany")
        print("Pouziti: python3 resolver.py nic.cz --dnssec")
        sys.exit()

    # Kontrola, ze zadana domena je platny nazev
    # (napr. 'www..zive.cz' nebo prilis dlouhy nazev platny neni)
    try:
        name = dns.name.from_text(domain)
    except (dns.exception.SyntaxError, dns.name.NameTooLong):
        print(f"{color.RED}Neplatný název domény: {domain}{color.END}")
        sys.exit(1)

    # Samotny koren '.' neni domena, kterou by slo prelozit na IP adresu
    if name == dns.name.root:
        print(f"{color.RED}Zadej doménu, samotný kořen '.' nemá IP adresu{color.END}")
        sys.exit(1)

    # Vychozi ukecanost
    verbose = 0

    # Zvysena ukecanost, budou se vypisovat surove textove DNS odpovedi
    if "--ukecany" in sys.argv:
        verbose = 1

    # Overovani podpisu DNSSEC
    dnssec = "--dnssec" in sys.argv

    # Objekt naseho resolveru a vyhledani
    # Pokud nektery server neodpovi vcas, knihovna vyhodi vyjimku Timeout
    resolver = KloboukResolver(domain, verbose, dnssec)
    try:
        ip, stats = resolver.resolve()
    except dns.exception.Timeout:
        print(f"{color.RED}Server neodpověděl včas, zkus to prosím znovu{color.END}")
        sys.exit(1)

    # Vykresleni zakladni orientacni statistiky
    print(f"Vyhledávání zabralo {int((stats['time_end']-stats['time_start'])*1000)} ms")
    print("")
    print(f"Dohromady jsem poslal {stats['query_counter']} DNS dotazů:")
    for i, nameserver in enumerate(stats["query_nameservers"]):
        print(f" {(i+1)}. {nameserver}")

    # Celkovy vysledek overeni DNSSEC
    if dnssec:
        print("")
        status = stats["dnssec_status"]
        if status == "SECURE":
            print(f"{color.BOLD}Výsledek DNSSEC: {color.GREEN}SECURE{color.END} - celý řetěz důvěry od kořene až k odpovědi je ověřený")
        elif status == "INSECURE":
            print(f"{color.BOLD}Výsledek DNSSEC: {color.YELLOW}INSECURE{color.END} - doména není podepsaná, odpověď nejde ověřit")
        elif status == "BOGUS":
            print(f"{color.BOLD}Výsledek DNSSEC: {color.RED}BOGUS{color.END} - ověření selhalo, podpis nebo otisk klíče nesedí! Validující resolver by odpověď zahodil a vrátil chybu SERVFAIL")
        else:
            print(f"{color.BOLD}Výsledek DNSSEC: NEOVĚŘENO{color.END} - překlad skončil dřív, než se podařilo cokoliv ověřit")
