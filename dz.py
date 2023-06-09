'''
Sto omogucavamo i kako:
    1) korisnik upisuje naredbu po naredbu (omoguceno pomocu while petlje na kraju koda;
        dozvoljeni su i prelasci u novi red, a kraj unošenja naredbi označava se pomoću ';')
    2) varijable (npr. €var -> kao sto bi u php-u imali $var; definiranje varijable bi bilo
        ovako: €cvijet = Rosa rubiginosa)
    3) for petlja (npr. $var{$k = $k + 1} -> znaci da se €var puta izvrši naredba $k = $k+1)
    4) definicije funkcija (npr. plus(a, b){ret a+b})
    5) funkcijski poziv (od definicije se razlikuje po tome sto nakon oble zagrade ne dode vitica)
    6) operator ~ (alias surf) koristi se za dobivanje površine cvijeta t.d. se stavi surf €cvijet Ili
    surf Rosa rubiginosa
    7) print u datoteku pomocu kljucne rijeci 'datw'
    8) citanje iz datoteke pomocu kljucne rijeci 'datread'
    9) konacni tip podataka (flower formula
        nalazit ce se u uglatim zagradama i sastojat ce se od velikih i malih slova i brojeva;
        u stvarnosti su komplicirane al mi mozemo koristit jednostavniju verziju;
        kratki opis: https://www.vedantu.com/neet/floral-formula-of-fabaceae)
    7) potencijalno beskonacni tip podatka (sekvence dna - zapocinje s %)
    8) operator ? (alias ed) koristi se za racunanje genetske udaljenosti(evolutionary distance);
        to je višemjesni operator sto znaci da se moze pozvati na proizvoljno mnogo biljaka;
        tim biljkama ce se genomi usporedivati do duljine biljke s najkracim genomom i
        vratit ce se one dvije biljke s najmanjom razlikom; kao i surf moze se pozvati na varijablama
        ili latinskim nazivima
    9) operator ß (alias cmp) koristi se za pronalazak genetski najblizeg cvijeta;
        ubiginosa
    10) sql naredba za unos cvijeta u tablicu pomocu operator '->'
        (npr. ->Rosa rubiginosa->[K5C5AG10]->ATGCTGACGTACGTTA unosi u tablicu redak
        gdje je ime Rosa rubiginosa, cvjetna formula je K5C5AG10)

    napomena: varijable u koje se pohranjuju brojevi su ozn s $, a ostale s €
    napomena: pojedine naredbe u jeziku moraju biti odvojene s \n
    napomena: kao argumente fja (odvojene zarezima) dozvoljavamo samo brojeve, cvjetne formule, sekvence gena,
    latinske nazive, FLOWER_VAR, NUM_VAR (dakle ne dozvoljavamo da argument bude npr. $k + $l -
    on je to dozvolio u primjeru 09)
'''
import os
from vepar import *
from backend import PristupLog

class T(TipoviTokena):
    ZA = 'za' #for Petlja, eg:
              #€var = 2, €k = 0
              #za €var{k = k+1} --> k = 2
    #FUNK = 'funk' #deklaracija funkcije eg: funk plus(a, b){ret a+b}
    RET = 'ret' #povratna vrijednost funkcije
    DATO, DATC = 'dato', 'datc' #otvori/zatvori dadodedu
    DATW, DATREAD = 'datw', 'datread' #pisi/citaj dadodedu
    EOL = ";" #kraj unosa
    SURF = '~'
    NR = "\n"
    #ideja:     #mislim da je ovo bolji nacin, jer time omogucavamo koristenje vise datoteka istovremeno
    #dato("abc.txt") -mozda nepotrebno
    #datw("ime.txt","pqr")
    #€var = datread("ime.txt") --> €var = "pqr"
    #datc() -mozda nepotrebno
    CMP, JEDN, ED, GEN = 'ß=?%'
    PLUS, MINUS, PUTA, KROZ, ZAREZ = '+-*/,'
    OO, OZ, VO, VZ, UO, UZ = '(){}[]' #OO = obla otvorena
    SQLINSERT = '->'
    class LAT_NAZ(Token): #latinski naziv sukulenta, prva rijec pocinje velikim slovom, druga malim
        def vrijednost(self, mem, unutar): return self.sadržaj
    class BROJ(Token):
        def vrijednost(self, mem, unutar): return int(self.sadržaj)
    class IME(Token): #ime fje
        def vrijednost(self, mem, unutar): return mem[self]
    class NUMVAR(Token):
        def vrijednost(self, mem, unutar): return mem[self]
    class FLOWERVAR(Token):
        def vrijednost(self, mem, unutar): return mem[self]
    class FLOWERF(Token):
        def vrijednost(self, mem, unutar): return self.sadržaj
    class GENSEKV(Token):
        def vrijednost(self, mem, unutar): return self.sadržaj
    class DAT(Token): #ime datoteke
        def vrijednost(self, mem, unutar): return self.sadržaj
    class SQLIME(Token): #za osposobljavanje sql-a
        def vrijednost(self, mem, unutar): return self.sadržaj

@lexer
def bilj(lex):
    for znak in lex:
        if znak == '\n':
            yield lex.token(T.NR)
        elif znak.isspace():
            lex.zanemari()
        elif znak.isdecimal():
            lex.prirodni_broj(znak)
            yield lex.token(T.BROJ)
        elif znak.isupper():
            lex * str.isalpha
            if lex >= " ":  #latinski naziv
                znak = next(lex)
                if znak.isupper():
                    raise lex.greška('očekivano malo slovo')
                else:
                    lex * str.isalpha
                yield lex.literal_ili(T.LAT_NAZ)
            else:   #sekvenca gena
                yield lex.token(T.GENSEKV)
        elif znak == '€':   #varijabla
            lex * str.isalnum
            yield lex.literal_ili(T.FLOWERVAR)
        elif znak == '$':   #varijabla
            lex * str.isalnum
            yield lex.literal_ili(T.NUMVAR)
        elif znak == '#': #komentar po uzoru na primjer 09
            lex - "\n"      #for some reason vraca error da nije naso "\n" -> to se
                            #dogodi samo za unos kroz terminal, ako mu se da ulaz ovak kak sam stavila radi normalno -Ivana
                            #mislim da je problem u tome sto prilikom ucitavanja stringa iz terminala python u liniji ulaz = str(input()) nigdje ne pohranjuje znak "\n"
                            #pa bi ovo trebali drugacije citati, kao do kraja retka ili staviti ulaz = str(input())+"\n"
                            #stavila sam ovu drugu opciju i cini mi se da radi kak treba ~Dora
            lex.zanemari()
        elif znak == '[':
            lex - ']'
            yield lex.token(T.FLOWERF)
        elif znak == '-':
            if lex >= '>':
                yield lex.token(T.SQLINSERT)
            else:
                yield lex.token(T.MINUS)
        elif znak == '"':
            lex - '"'
            yield lex.token(T.DAT)
        elif znak == '%':
            lex * str.isalpha
            yield lex.token(T.GENSEKV)
        else:
            lex * str.isalpha
            if lex.sadržaj == "surf":
                yield lex.token(T.SURF)
            elif lex.sadržaj == "cmp":
                yield lex.token(T.CMP)
            elif lex.sadržaj == "ed":
                yield lex.token(T.ED)
            else:
                yield lex.literal_ili(T.IME) #ako nije nis drugo, onda je literal

###BKG
# program -> funkcija | funkcija program
# funkcija -> IME OO parametri? OZ VO naredba VZ
# parametri -> ime | parametri ZAREZ ime | nesto_cvjetno | parametri ZAREZ nesto_cvjetno        #*** za sada nije omogueno da druga funkcija bude parametar funkcije
# ime -> NUMVAR | FLOWERVAR
# naredba -> pridruži | VO naredbe VZ | RET argument
#         | gen_dist | closest | NUMVAR VO naredba VZ ##ovo zadnje je for petlja (treba omoguciti i da umjesto numvar pise samo broj)
#         | sql | DATW OO DAT ZAREZ TEKST OZ | pridruziIzDat
# naredbe -> naredba | naredbe NR naredba
# pridruži -> NUMVAR JEDNAKO aritm | FLOWERVAR JEDNAKO nesto_cvjetno
# pridružiIzDat ->  NUMVAR JEDNAKO DATREAD OO DAT OZ | NUMVAR JEDNAKO DATREAD OO DAT OZ
# nesto_cvjetno -> FLOWERF | GENSEKV | LAT_NAZ
# gen_dist -> cvjetni_clan |  gen_dist ED cvjetni_clan
# closest -> cvjetni_clan |  closest CMP cvjetni_clan
# sql -> SQLINSERT LAT_NAZ SQLINSERT FLOWERF SQLINSERT GENSEKV
# cvjetni_clan -> GENSEKV | LAT_NAZ | FLOWERVAR | FLOWERF
# aritm -> član | aritm PLUS član | aritm MINUS član
# član -> faktor | član ZVJEZDICA faktor
# faktor -> BROJ | NUMVAR | IME poziv | OO aritm OZ | MINUS faktor | SURF FLOWERVAR | SURF nesto_cvjetno
# poziv -> OO OZ | OO argumenti OZ
# argumenti -> argument | argumenti ZAREZ argument
# argument -> nesto_cvjetno | BROJ
#
# Mozemo biljku identificirati s bilo kojim od: cvjetna varijabla, lat naz, cvj form ili gen
#(svaki od njih jedinstveno odreduje biljku) ako se pozove ed i proslijedi ko
#parametar bilokoje od ta tri, convertamo u onaj u koji zelimo
# (u bazi nekoj pisu trojke) i provedemo ed


### Parsing time :,) -> dosta toga po uzoru na primjer 09
class P(Parser):
    def program(p) -> 'Memorija':
        p.funkcije = Memorija(redefinicija=False)
        while not p > KRAJ:
            if p > T.IME:
                funkcija = p.funkcija()
                p.funkcije[funkcija.ime] = funkcija
            else:
                print("naredba:")
                naredba = p.naredba()
        return p.funkcije

    def funkcija(p) -> 'Funkcija':
        p >= T.NR
        atributi = p.imef, p.parametrif = p >> T.IME, p.parametri()
        return Funkcija(*atributi, p.naredba())

    def varijabla(p) -> 'Varijabla':
        return p.ime()

    def ime(p) -> 'NUMVAR|FLOWERVAR':
        p >= T.NR
        return p >> {T.NUMVAR, T.FLOWERVAR}

    def nesto_cvjetno(p) -> 'FLOWERF|GENSEKV|LAT_NAZ':
        p >= T.NR
        return p >> {T.FLOWERF, T.GENSEKV, T.LAT_NAZ}

    def parametri(p) -> 'ime*':
        p >> T.OO
        if p >= T.OZ: return []
        if p > T.NUMVAR or p > T.FLOWERVAR:
            param = [p.ime()]
        else:
            param = [p.nesto_cvjetno()]
        while p >= T.ZAREZ:
            if p > T.NUMVAR or p > T.FLOWERVAR:
                param.append(p.ime())
            else:
                param.append(p.nesto_cvjetno())
        p >> T.OZ
        return param

    def naredba(p) -> 'petlja|blok|Vrati|Pridruživanje|UpisiUDat|PridruziIzDat':
        p >= T.NR
        if p > T.DATW:
            p >= T.NR
            p >> T.DATW
            p >> T.OO
            dat = p >> T.DAT
            p >> T.ZAREZ
            unos = p.ime()
            p >> T.OZ
            return UpisiUDat(dat, unos)
        elif p > T.NUMVAR:
            p >= T.NR
            ime = p.ime()
            if p > T.JEDN:
                p >> T.JEDN
                if p > T.DATREAD:
                    p >> T.DATREAD
                    p >> T.OO
                    dat = p >> T.DAT
                    p >> T.OZ
                    return PridruziIzDat(dat,ime)
                else:
                    return Pridruživanje(ime, p.tipa(ime))
            else:
                return p.petlja(ime)
        elif p > T.VO:
            return p.blok()
        elif p >= T.RET:
            return Vrati(p.imef)
        elif p >= T.SQLINSERT:
            prvi = p >> T.LAT_NAZ
            p >> T.SQLINSERT
            drugi = p >> T.FLOWERF
            p >> T.SQLINSERT
            treci = p >> T.GENSEKV
            return Insert(prvi, drugi, treci)
        elif p > T.NUMVAR:
            ime = p.ime()
            p >> T.JEDN
            if p > T.DATREAD:
                p >> T.DATREAD
                p >> T.OO
                dat = p >> T.DAT
                p >> T.OZ
                return PridruziIzDat(dat,ime)
            else:
                return Pridruživanje(ime, p.tipa(ime))
        elif p > T.FLOWERVAR:
            ime = p.ime()
            print(ime)
            if p > T.JEDN:
                print(" = ")
                p >> T.JEDN
                if p > T.DATREAD:
                    p >> T.DATREAD
                    p >> T.OO
                    dat = p >> T.DAT
                    p >> T.OZ
                    return PridruziIzDat(ime,dat)
                else:
                    t = p.tipa(ime)
                    print(t)
                    return Pridruživanje(ime, t)
            elif p > T.ED:
                return p.gen_dist(ime)
            elif p > T.CMP:
                return p.closest(ime)
        else: #preostaje jedino CMP ili ED
            cvjetni = p.nesto_cvjetno()
            if p > T.ED:
                return p.gen_dist(cvjetni)
            else:
                p >> T.CMP
                return p.closest(cvjetni)

    def gen_dist(p, first):
        flowers = [first]
        while p >= T.ED:
            if p > T.FLOWERVAR:
                flowers.append(p.tipa(p.ime()))
            else:
                flowers.append(p.nesto_cvjetno())
        return Distance(flowers)

    def closest(p, first):
        flowers = [first]
        while p >= T.CMP:
            if p > T.FLOWERVAR:
                flowers.append(p.tipa(p.ime()))
            else:
                flowers.append(p.nesto_cvjetno())
        return Closest(flowers)

    def tipa(p, ime) -> 'NUMVAR|FLOWERVAR':
        p >= T.NR
        if ime ^ T.NUMVAR: return p.aritm()
        elif ime ^ T.FLOWERVAR: return p.nesto_cvjetno()
        else: assert False, f'Nepoznat tip od {ime}'

    def petlja(p, kolikoPuta) -> 'Petlja': #stavljamo li da je u petlji moguca samo jedna naredba? - valjda je Dorotea ovo pitala, trebalo bi bit moguce proizvoljno mnogo naredbi -Ivana
        p >> T.VO
        p >= T.NR
        izvrsiti = p.naredba()
        p >= T.NR
        p >> T.VZ
        return Petlja(kolikoPuta, izvrsiti)

    def blok(p) -> 'Blok|naredba':
        p >= T.NR
        p >> T.VO
        if p >= T.VZ: return Blok([])
        n = [p.naredba()]
        print("blok")
        while p >= T.NR and not p > T.VZ:
            print("Flag")
            n.append(p.naredba())
        p >> T.VZ
        p >= T.NR
        return Blok.ili_samo(n)

    def argumenti(p, parametri) -> 'tipa*':
        arg = []
        p >> T.OO
        for i, parametar in enumerate(parametri):
            if i:
                p >> T.ZAREZ
            arg.append(p.tipa(parametar))
        p >> T.OZ
        return arg

    def aritm(p) -> 'Zbroj|član':
        članovi = [p.član()]
        while ...:
            if pp := p >= T.PLUS:
                članovi.append(p.član())
            elif pp := p >= T.MINUS:
                članovi.append(Suprotan(p.član()))
            else:
                return Zbroj.ili_samo(članovi)

    def član(p) -> 'Umnožak|faktor':
        faktori = [p.faktor()]
        while p >= T.PUTA: faktori.append(p.faktor())
        return Umnožak.ili_samo(faktori)

    def faktor(p) -> 'Suprotan|Poziv|aritm|BROJ':
        if p >= T.MINUS:
            return Suprotan(p.faktor())
        elif call := p >= T.IME:
            if call in p.funkcije:
                funkcija = p.funkcije[ime]
                return Poziv(funkcija, p.argumenti(funkcija.parametri))
            else:
                return Poziv(nenavedeno, p.argumenti(p.parametrif))
        elif p >= T.OO:
            u_zagradi = p.aritm()
            p >> T.OZ
            return u_zagradi
        elif toEvaluate := p >= T.NUMVAR:
            return toEvaluate
        elif p >= T.SURF:
            if calc := p >= T.FLOWERVAR:
                return SurfaceArea(calc)
            else:
                return SurfaceArea(p.nesto_cvjetno())
        else:
            return p >> T.BROJ

def izvrši(funkcije, *argv):
    print('Program je vratio:', funkcije['program'].pozovi(argv))

### AST
# Funkcija: ime: IME parametri:[NUMVAR|FLOWERVAR|nesto_cvjetno] tijelo:naredba
# naredba: Petlja: istinitost:JE|NIJE uvjet:log tijelo:naredba
#          Blok: naredbe:[naredba]
#          Pridruživanje: ime:AIME|LIME pridruženo:izraz
#          UpisiUDat: imeDat:dat ime:ime
#          PridruziIzDat: ime:ime imeDat:dat
#          Insert: prvi:LAT_NAZ drugi:FLOWERF treci:GENSEKV
#          Closest: flowers:[nesto_cvjetno]
#          Distance: flowers:[nesto_cvjetno]
#          Vrati: što:izraz
# izraz: aritm: Zbroj: pribrojnici:[aritm]
#               Suprotan: od:aritm
#               Umnožak: faktori:[aritm]
#        Poziv: funkcija:Funkcija? argumenti:[izraz]

class UpisiUDat(AST):
    imeDat: 'DAT'
    unos: 'IME'
    def izvrši(self, mem, unutar):
        cistoIme = self.imeDat.vrijednost(mem, unutar)
        novoIme = cistoIme[1:len(cistoIme) - 1] #uklonjeni navodnici iz imena kako bi se mogao izvrsiti open
        f = open(novoIme, 'w+')
        f.write(self.unos.vrijednost(mem, unutar))
        f.close()

class PridruziIzDat(AST):
    ime: 'IME'
    imeDat: 'DAT'
    def izvrsi(self,mem,unutar):
        f=open(self.imeDat.vrijednost(mem, unutar),'r')
        mem[self.ime] = f.read()
        f.close()

class Stupac(AST):
    """Specifikacija stupca u tablici."""
    ime: 'SQLIME'
    tip: 'SQLIME'
    rows: 'SQLIME*'
    #veličina: 'BROJ?'

class Create(AST):
    """Naredba CREATE TABLE."""
    tablica: 'SQLIME'
    specifikacije: 'Stupac*'

    def razriješi(naredba):
        pristup = rt.imena[naredba.tablica] = Memorija(redefinicija=False)
        for stupac in naredba.specifikacije:
            pristup[stupac.ime] = PristupLog(stupac)

class Insert(AST):
    prvi: 'LAT_NAZ'
    drugi: 'FLOWERF'
    treci: 'GENSEKV'
    def izvrši(insert, mem, unutar):
        print("insert")

class Closest(AST):
    flowers: 'nesto_cvjetno*'
    def izvrši(self,mem,unutar):
        genKodovi=[] #lista genetskih kodova koje usporedujemo
        for cvijet in self.flowers:
            if " " in cvijet: #imamo latinski naziv
                broj=-1
                for tablica,log in rt.imena:
                    for stupac,pristup in log:
                        if stupac=="LN": #svakako dolazi prije stupca GS
                            i=0
                            for thing in pristup.objekt.rows:
                                if thing==cvijet:
                                    broj=i
                                    break
                                i+=1
                            if broj==-1: raise GreškaIzvođenja('Ne postoji objekt' + cvijet + 'u tablici')
                        elif stupac=="GS":
                            brojac=0
                            for thing in pristup.objekt.rows:
                                if(brojac==broj):
                                    genKodovi.append(thing)
                                    break
                                brojac+=1

            elif "K" in cvijet: #imamo cvijetnu fomulu
                broj=-1
                for tablica,log in rt.imena:
                    for stupac,pristup in log:
                        if stupac=="FF": #svakako dolazi prije stupca GS
                            i=0
                            for thing in pristup.objekt.rows:
                                if thing==cvijet:
                                    broj=i
                                    break
                                i+=1
                            if broj==-1: raise GreškaIzvođenja('Ne postoji objekt' + cvijet + 'u tablici')
                        elif stupac=="GS":
                            brojac=0
                            for thing in pristup.objekt.rows:
                                if(brojac==broj):
                                    genKodovi.append(thing)
                                    break
                                brojac+=1
            else: #imamo genetski kod
                genKodovi.append(cvijet)

        l=min(genKodovi,len) #duljina najkraceg genetskog koda
        maks=0 #max broj gena koji se podudaraju
        for i in range(1,len(self.flowers)):
            brojac=0
            for k in range(0,l):
                if(genKodovi[i][k]==genKodovi[0][k]):
                    brojac+=1
                    if(brojac>maks):
                       cvijet1=self.flowers[0]
                       cvijet2=self.flowers[i]
        return cvijet1+" "+cvijet2 #ne znam sta bi ovdje vracala, pa neka za sada bude ovo

class Distance(AST):
    flowers: 'nesto_cvjetno*'
    def izvrši(self,mem,unutar):
        genKodovi=[] #lista genetskih kodova koje usporedujemo
        for cvijet in self.flowers:
            if " " in cvijet: #imamo latinski naziv
                broj=-1
                for tablica,log in rt.imena:
                    for stupac,pristup in log:
                        if stupac=="LN": #svakako dolazi prije stupca GS
                            i=0
                            for thing in pristup.objekt.rows:
                                if thing==cvijet:
                                    broj=i
                                    break
                                i+=1
                            if broj==-1: raise GreškaIzvođenja('Ne postoji objekt' + cvijet + 'u tablici')
                        elif stupac=="GS":
                            brojac=0
                            for thing in pristup.objekt.rows:
                                if(brojac==broj):
                                    genKodovi.append(thing)
                                    break
                                brojac+=1

            elif "K" in cvijet: #imamo cvijetnu fomulu
                broj=-1
                for tablica,log in rt.imena:
                    for stupac,pristup in log:
                        if stupac=="FF": #svakako dolazi prije stupca GS
                            i=0
                            for thing in pristup.objekt.rows:
                                if thing==cvijet:
                                    broj=i
                                    break
                                i+=1
                            if broj==-1: raise GreškaIzvođenja('Ne postoji objekt' + cvijet + 'u tablici')
                        elif stupac=="GS":
                            brojac=0
                            for thing in pristup.objekt.rows:
                                if(brojac==broj):
                                    genKodovi.append(thing)
                                    break
                                brojac+=1
            else: #imamo genetski kod
                genKodovi.append(cvijet)

        l=min(genKodovi,len) #duljina najkraceg genetskog koda
        maks=0 #max broj gena koji se podudaraju
        for i in range(0,len(self.flowers)):
            brojac=0
            for j in range(i+1,len(self.flowers)): #ne usporedujem cvijet sam sa sobom
                for k in range(0,l):
                    if(genKodovi[i][k]==genKodovi[j][k]):
                        brojac+=1
                        if(brojac>maks):
                           cvijet1=self.flowers[i]
                           cvijet2=self.flowers[j]
        return cvijet1+" "+cvijet2 #ne znam sta bi ovdje vracala, pa neka za sada bude ovo

class SurfaceArea(AST):
    flower: 'nesto_cvjetno'
    def izvrši(surf, mem, unutar):
        print("surf")
class OneLine(AST):
    ime: 'linija'
    tijelo: 'naredba'
    def izvrši(onelie, mem, unutar):
        print("onelie")

class Funkcija(AST):
    ime: 'IME'
    parametri: 'VAR*'
    tijelo: 'naredba'
    def pozovi(funkcija, argumenti):
        lokalni = Memorija(zip(funkcija.parametri, argumenti))
        try: funkcija.tijelo.izvrši(mem=lokalni, unutar=funkcija)
        except Povratak as exc: return exc.preneseno
        else: raise GreškaIzvođenja(f'{funkcija.ime} nije ništa vratila')

class Poziv(AST):
    funkcija: 'Funkcija?'
    argumenti: 'izraz*'
    def vrijednost(poziv, mem, unutar):
        pozvana = poziv.funkcija
        if pozvana is nenavedeno: pozvana = unutar  # rekurzivni poziv
        argumenti = [a.vrijednost(mem, unutar) for a in poziv.argumenti]
        return pozvana.pozovi(argumenti)

    def za_prikaz(poziv):  # samo za ispis, da se ne ispiše čitava funkcija
        r = {'argumenti': poziv.argumenti}
        if poziv.funkcija is nenavedeno: r['*rekurzivni'] = True
        else: r['*ime'] = poziv.funkcija.ime
        return r

class Petlja(AST):
    kolikoPuta: 'NUMVAR'
    izvrsiti: 'naredba'
    def izvrši(petlja, mem, unutar):
        for i in range(kolikoPuta.vrijednost()):
            petlja.izvrsiti.izvrši(mem, unutar)

class Blok(AST):
    naredbe: 'naredba*'
    def izvrši(blok, mem, unutar):
        for naredba in blok.naredbe: naredba.izvrši(mem, unutar)

class Pridruživanje(AST):
    ime: 'IME'
    pridruženo: 'izraz'
    def izvrši(self, mem, unutar):
        mem[self.ime] = self.pridruženo.vrijednost(mem, unutar)

class Vrati(AST):
    što: 'izraz'
    def izvrši(self, mem, unutar):
        raise Povratak(self.što.vrijednost(mem, unutar))

class Zbroj(AST):
    pribrojnici: 'aritm*'
    def vrijednost(zbroj, mem, unutar):
        return sum(p.vrijednost(mem, unutar) for p in zbroj.pribrojnici)

class Suprotan(AST):
    od: 'aritm'
    def vrijednost(self, mem, unutar): return -self.od.vrijednost(mem, unutar)

class Umnožak(AST):
    faktori: 'aritm*'
    def vrijednost(umnožak, mem, unutar):
        return math.prod(f.vrijednost(mem, unutar) for f in umnožak.faktori)


class Povratak(NelokalnaKontrolaToka): """Signal koji šalje naredba vrati."""

#sql

rt.imena = Memorija(redefinicija=False)
nazivi = ["Rosa rubiginosa"]
nazivi.append("Rosa rugosa")
stupci = [Stupac("ln", "LAT_NAZ", nazivi)]
formule = ["[K5C5AG10]"]
formule.append("[K5C2AG9]")
stupci.append(Stupac("FF", "FLOWERF", formule))
geni = ["ATGCTGACGTACGTTA"]
geni.append("ATGACGCTGTACGTTA")
stupci.append(Stupac("GS", "GENSEKV", geni))
Create("Botanika", stupci).razriješi()
#for tablica, log in rt.imena:
 #   print('Tablica', tablica, '- stupci:')
 #   for stupac, pristup in log:
  #      print('\t', stupac, pristup)
  #      for thing in pristup.objekt.rows: ##prolazak po rows
    #        print('\t', thing)

#isprobavanje parsera:

proba = P('''#komentar
program(){
->Rosa rubiginosa->[K5C5AG10]->%ATGCTGACGTACGTTA
€cvijet = Rosa rubiginosa
datw("dat.txt",€cvijet)
$num1 = surf €cvijet
€cvijet ? Rosa rubiginosa ? Rosa rugosa
$num2 = ~ €cvijet
$var{$k = $k + 1}
€geni = %ATGCTGACGTACGTTA
€formula = [K5C5AG10]
}
''')
prikaz(proba, 5)
izvrši(proba)
"""
bilj('''#komentar
program(){
->Rosa rubiginosa->[K5C5AG10]->ATGCTGACGTACGTTA
€cvijet = Rosa rubiginosa
$num1 = surf €cvijet
€cvijet ? Rosa rubiginosa ? Rosa rugosa
$num = ~ €cvijet
$var{$k=$k+1}
datw("dat.txt",€cvijet)
$num1 = datread("dat.txt")
}
''')"""

""" prikaz(P('datw("dat.txt",€cvijet)')) """


###treba otkomentirati za unos kroz terminal
""" ukupni = ""
while 1:
    ulaz = str(input())+"\n" #nadodala sam ovdje +"\n" kao sto sam gore komentirala i cini mi se okej ~Dora
    ukupni +=ulaz
    for i in ulaz:
        if i == ";":
            bilj(ukupni)
            ukupni = ""  """

### Beskontekstna gramatika:

### Apstraktna sintaksna stabla (i njihovi atributi):
