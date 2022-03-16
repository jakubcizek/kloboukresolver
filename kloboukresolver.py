# K behu je treba knihovna dnspython:
# https://dnspython.readthedocs.io/en/latest/installation.html

# TENTO KOD VZNIKL JEN ZA UCELEM RYCHLE PREZENTACE AUTORITATIVNIHO DNS PREKLADU
# 1) Je to bastl!
# 2) Psal jsem ho bez hlubsi znalosti knihovny dnspython
# 3) Tomu odpovidaji nektere postupy, ktere by slo resit cisteji a lepe
# 4) V nekterych fazich napriklad opoustim parser knihovny dnspython a pracuji se surovym textem
# 5) Kod neimplementuje vsechny moznosti, neni osetreny na vsechny chyby 

import random
import dns.name
import dns.message
import dns.query
import sys
import time

# 13 vychozich root serveru
root_servers = [
    {
        "ip":"198.41.0.4",
        "op": "Verisign, Inc."
    },
    {
        "ip":"199.9.14.201",
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

# TErminalove barvicky
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
    def __init__(self, domain, verbose=0):
        self.domain = domain
        self.verbose = verbose
        self.tabelator = " "
        self.tabsize = 5    
    
    # Reset promennych pro statistiku a tabelovani/cislovani
    def reset(self):
        self.step = 0
        self.stats_query_counter = 0
        self.stats_query_nameservers = []

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

        # Slovnik se statisrtikou
        stats = {
            "query_counter": self.stats_query_counter,
            "query_nameservers": self.stats_query_nameservers,
            "time_start": start,
            "time_end": end
        }
    
        # Vracim pole s IP a slovnik se statistikou
        return ip, stats

    # Privatni metoda pro zahajeni prekladu
    # Nevolat zvenci
    def __resolve(self, domain):
        # Pole s vysledky, nalezenymi IP adresami
        ip = []

        # Jen drobne ocisteni domeny
        # Bastl, toto by se melo resit ponoi dns.name,
        # ale nechtelo se m ito hledat v dokumentaci
        if domain[-1] == ".":
            domain = domain[:-1]
        
        # Volba nahodneho korenoveho nameserveru
        root_server = random.choice(root_servers)
        nameserver = root_server["ip"]
        operator = root_server["op"]
        nameserver_domain = ""

        # Vytvoreni prvniho textoveh odsazeni
        # a Vypsani uvitaci zpravy o volbe korenoveho nameserveru a hledani IP adresy pro zadanou domenu
        self.step += 1
        tab = self.tabelator * self.tabsize * self.step
        print("")
        print(f"{color.BOLD}{tab}{self.step}. Budu hledat IP adresu pro {color.YELLOW}{domain}{color.END}")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Na začátku znám pouze 13 IP adres nejvyšších kořenových serverů systému DNS (root-servers.org)")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Volím náhodný kořenový DNS server: {color.YELLOW}{nameserver}{color.END}")
        print(f"{tab}{(len(str(self.step))+2) * ' '}Operátor: {color.YELLOW}{operator}{color.END}")
        print("")

        # Priprava domeny
        # Toto by slo udelat i pomoci knihony dnspython, 
        # ale nechtela se m istudovat dokumentace, a tak to osklive zbastlim
        # Pokud je vstupni domena treba www.zive.cz,
        # prevratim ji a rozdelim na pole subdomen podle '.':
        # 'cz', 'zive', 'www'
        subdomains = reversed(domain.split("."))
        current_subdomain = ""

        # Projdu pole subdomen
        for subdomain in subdomains:

            # Pripravim si DNS objekt aktualne resene domeny
            # V pripade www.zive.cz by to tedy bylo po kazdem prochodu:
            # cz., zive.cz., www.zive.cz.
            current_subdomain = dns.name.from_text(f"{subdomain}.{current_subdomain}")
        
            # Pomocne promenne pro cislovani dotazu a odsazeni
            # pro kaskadovite vypsani vysledku
            self.step += 1
            tab = self.tabelator * self.tabsize * self.step

            # Ptam se serveru 'nameserver', jestli nema zaznamy typu NS pro domenu 'current_domain'
            print(f"{color.BOLD}{tab}{self.step}. Ptám se {color.YELLOW}{nameserver}{color.END}{color.BOLD}, kdo má na seznamu {color.YELLOW}{current_subdomain.to_text()}{color.END} ")
            query = dns.message.make_query(current_subdomain, dns.rdatatype.NS)
            response = dns.query.udp(query, nameserver)
            self.stats_query_counter += 1
            self.stats_query_nameservers.append(nameserver.ljust(15, " ") + f"(vyhledání NS záznamu pro doménu {current_subdomain.to_text()})")
            
            # Pokud jsem spustil program s parametrem --ukecany
            # vypise se pro kontrolu cela RAW odpoved v textovem formatu DNS
            # Viz https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
            if self.verbose == 1:
                print("*** ODPOVĚĎ DNS ***")
                print(str(response))
                print("*******************")
            
            # Zkusim dohledat prvni A zaznamy s IP adresami v sekci ADDITIONAL
            # Pouziji prvni nalezenou
            if len(response.additional) > 0:
                for additional in response.additional:
                    if additional.rdtype == dns.rdatatype.A:
                        print(f"{tab}{(len(str(self.step))+2) * ' '}Skvělé, odpověď obsahuje záznam A s IP adresou")
                        # Toto neni uplne ciste reseni
                        nameserver = additional[0].to_text()
                        nameserver_domain = additional.to_text().split(" ")[0]
                        print(f"{tab}{(len(str(self.step))+2) * ' '}Doména {color.YELLOW}{current_subdomain.to_text()}{color.END} je na seznamu {color.YELLOW}{nameserver} ({nameserver_domain}){color.END}")
                        print("")
                        break

            # Pokd jsme zadny A zaznam s IP adresou nameserveru nenasel....
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
                            nameserver = self.__resolve(nameserver_domain)[0] 
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

        # Prosel jsem cely strome domeny
        # Nyni posledni znamy nameserver pouziji pro vyhledani IP adresy domeny
        self.step +=1
        tab = self.tabelator * self.tabsize * self.step
        print(f"{color.BOLD}{tab}{self.step}. Ptám se {color.YELLOW}{nameserver}{color.END}{color.BOLD}, jakou IP adresu má {color.YELLOW}{current_subdomain.to_text()}{color.END}")
        query = dns.message.make_query(current_subdomain, dns.rdatatype.A)
        response = dns.query.udp(query, nameserver)
        if self.verbose == 1:
                print("*** ODPOVĚĎ DNS ***")
                print(str(response))
                print("*******************")
        self.stats_query_counter += 1
        self.stats_query_nameservers.append(nameserver.ljust(15, " ") + f"(vyhledání A záznamu pro doménu {current_subdomain.to_text()})")
        
        if len(response.answer) > 0:
            # Pokud je nameserver, ktereho se prave ptam na zaznam A, autoritativni,
            # odpoved musi obsahovat flag AA (Authoritative Answer). Je to tedy
            # takovy test, ze jsem prosel DNS strom opravdu ke spravnemu nameserveru
            if dns.flags.AA in response.flags:
                print(f"{tab}{(len(str(self.step))+2) * ' '}{color.GREEN}Odpověď obsahuje flag AA a je autoritativní{color.END}")
            
            # Domena muze mit vicero A zaznamu a tedy i vice IP adres,
            # vysledkem je tedy vzdy pole IP
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.A:
                    for ip_address in answer:
                        ip.append(str(ip_address))
                        print(f"{color.BOLD}{tab}{(len(str(self.step))+2) * ' '}IP: {color.GREEN}{str(ip_address)}{color.END}")
            print("")
        
        # Pokud je pole s vysledky prazdne, 
        # tento nameserver tuto domenu asi vubec nespravuje
        # Pravdepodobne jsem zadal nesmyslnou domenu?
        else:
            print(f"{tab}{(len(str(self.step))+2) * ' '}{color.RED}Nenašel jsem žádnou IP adresu ;-({color.END}")
            print("")
        
        # Vrat pole IP adres
        return ip

# ************* ZACATEK PROGRAMU *************
if __name__ == "__main__":

    # Vychozi ukecanost
    verbose = 0

    # Zvysena ukecanost, budou se vypisovat surove textove DNS odpovedi
    if "--ukecany" in sys.argv:
        verbose = 1

    # Objekt naseho resolveru a vyhledani
    resolver = KloboukResolver(sys.argv[1], verbose)
    ip, stats = resolver.resolve()

    # Vykresleni zakladni orientacni statistiky
    print(f"Vyhledávání zabralo {int((stats['time_end']-stats['time_start'])*1000)} ms")
    print("")
    print(f"Dohromady jsem se skrze UDP spojil s {stats['query_counter']} servery:")
    for i, nameserver in enumerate(stats["query_nameservers"]):
        print(f" {(i+1)}. {nameserver}")