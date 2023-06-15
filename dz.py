'''
Sto omogucavamo i kako:
    1) korisnik upisuje naredbu po naredbu (omoguceno pomocu while petlje na kraju koda;
        obavezni su prelasci u novi red, a kraj unošenja naredbi označava se pomoću ';' (';' mora
        doći u novom retku) što započinje izvršavanje do sad unesenih naredbi)

    2) varijable (cvjetnog tipa se označavaju kao €varijabla, a numeričkog kao $var)

    3) for petlja (npr. $var{$k = $k + 1} -> znači da se $var puta izvrši naredba $k = $k+1);
    umjesto numeričke varijable prije vitice možemo imati i običan broj

    4) definicije funkcija (npr. $plus($a, $b){ret $a+$b}); fja uvijek mora završiti s ret, ali on može biti
    prazan (ne mora vratiti konkretnu vrijednost) ili ako nije prazan mora biti usklađen s imenom fje (dakle,
    ako ime funkcije počinje s $ i fja nema prazan return onda mora vratiti ili broj ili numeričku varijablu ili
    numerički aritmetički izraz; analogno s cvjetnim funkcijama);  
    za povratne vr. dozvoljavamo i aritmetičke izraze (numeričke) i izraz s operatorom CMP

    5) funkcijski poziv (od definicije se razlikuje po tome sto nakon oble zagrade ne dode vitica);
    moze se pojaviti samostalno ili kao desna strana pridruživanja varijabli; kao argumente fja 
    (odvojene zarezima) dozvoljavamo brojeve, cvjetne formule, sekvence gena, latinske nazive, 
    FLOWER_VAR, NUM_VAR, aritmetičke (numeričke) izraze, aritmetički cvjetni operator cmp i 
    pozive fja (i cvjetnih i numeričkih);

    6) operator ~ (alias info) koristi se za dobivanje raznih informacija o biljci određenih
        njenom cvjetnom formulom t.d. se stavi npr. info €cvijet; umjesto cvjetne varijable može doći
        i sekvenca gena ili latinski naziv ili cvjetna formula
            -podaci o biljci se ispisuju

    7) print u datoteku pomocu kljucne rijeci 'datw'; npr. datw("ime.txt", nesto) gdje nesto može biti
    cvjetna varijabla, numericka varijabla, broj, cvjetna formula, sekvenca gena ili latinski naziv ili
    rezultat numeričke aritmetičke operacije ili rezultat aritmetičkog cvjetnog operatora CMP 
    ili poziva fje (bilo kojeg tipa)

    8) čitanje iz datoteke pomoću ključne riječi 'datread'; npr $x = datread("ime.txt"); obavlja
    se i provjera tipa pri pridruživanju

    9) konačni tip podatka (flower formula
        nalazit će se u uglatim zagradama i sastojat će se od velikih i malih slova i brojeva u skladu
        s pravilima na linku; (https://en.wikipedia.org/wiki/Floral_formula)

    7) potencijalno beskonačni tip podatka (sekvence dna - započinje s % i smije sadržavati samo
        slova A, C, T, G)

    8) operator ? (alias ed) koristi se za računanje genetske udaljenosti(evolutionary distance);
        to je višemjesni operator što znači da se može pozvati na proizvoljno mnogo biljaka;
        tim biljkama će se genomi uspoređivati do duljine biljke s najkraćim genomom i
        ispisat će se one dvije biljke s najmanjom razlikom; kao i info može se pozvati 
        na latinskom nazivu, sekvencama gena, cvjetnoj formuli ili cvjetnoj varijabli
            -unos: €cvijet ? Rosa rubiginosa ? Rosa rugosa, gdje je €cvijet latinski naziv, sekvenca gena ili
            cvjetna formula neke biljke
            -analogan unos: €cvijet cmp Rosa rubiginosa cmp Rosa rugosa

    9) operator ß (alias cmp) koristi se za pronalazak genetski najbližeg cvijeta, višemjesni je;
        npr "Rosa Rubiginosa ß Rosa rugosa ß Olea europaea" će odlučiti je li Rosa Rugosa
        ili Olea europaea genetski bliža cvijetu Rosa Rubiginosa; također se može proslijediti latinski naziv,
        genetska sekvenca ili cvjetna formula biljke
            -omogućen je i unos: Olea europaea ß, koji će genetski kod zadane biljke usporediti sa svim
            genetskim kodovima biljaka koji se nalaze u tablici podataka
            -unos: Citrus limon ß Acer palmatum ß, usporedit će genetske kodove Citrus limona i Acera palmatuma,
            neće pretraživati bazu
            -povratna vrijednost: cvjetni tip koji reprezentira genetski najbliži cvijet

    10) sql naredba za unos cvijeta u tablicu pomoću operator '->' (alias: unesi)
            -primjer: ->Rosa rubiginosa->[K5C5AG10]->%ATGCTGACGTACGTTA
            -primjer: unesi Rosa rubiginosa unesi [K5C5AG10] unesi %ATGCTGACGTACGTTA
        gornje naredbe unose u tablicu redak gdje je ime Rosa rubiginosa, cvjetna formula je [K5C5AG10])

    11) sql naredba za pronalazak podataka o cvijetu iz tablice pomoću operatora '<-' (alias: dohvati)
            -unos: <-Rosa rubiginosa, ispis: Rosa rubiginosa  [K5C5AG10]  ATGCTGACGTACGTTA
            -analogni unos: dohvati Rosa rubiginosa

    napomena: pojedine naredbe u jeziku moraju biti odvojene s \n
    napomena: korisnik ne može definirati funkciju s imenom 'program' jer je to rezervirano za main; zamisljeno 
    je da 'program' ne prima i ne vraca nista
    napomena: možemo biljku identificirati s bilo kojim od: cvjetna varijabla, latinski naziv, cvjetna formula 
    ili sekvencama gena (svaki od njih jedinstveno određuje biljku)
'''
import os
from vepar import *
#za bazu podataka koristimo veprov backend
from backend import PristupLog

#pomocna funkcija za kontrolu formata cvjetne formule u lekseru
def ffControl(lex):
    if not lex > '>':
        if lex >= '1':
            if lex > {'3', '4', '5', '6', '7', '8', '9'}:
                string = "First formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tTepals: 'P' or 'CaCo'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
                string += "Second formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tSepals and petals: 'K' or 'Ca' and then 'C' or 'Co'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
                string += "Note that each label must be followed by a number between 1 and 12 or by the symbol '>' which means 'more than 12'"
                raise LeksičkaGreška("Neispravno formulirana cvjetna formula. Proučite sljedeće upute za ispravnu formulaciju:\n"+string)
            else:
                lex >= {'0', '1', '2'}
        elif lex > {'2', '3', '4', '5', '6', '7', '8', '9'}:
            lex >> {'2', '3', '4', '5', '6', '7', '8', '9'}
        else:
            return
    else:
        lex >> '>'

class T(TipoviTokena):
    RET = 'ret' #povratna vrijednost funkcije
    DATW, DATREAD = 'datw', 'datread' #pisi u datoteku/citaj datoteku
    EOL = ";" #kraj unosa (bitno za terminal - izvrsava dosadasnje naredbe)
    INFO = '~' #informacije o cvijetu
    NR = "\n" #separator naredbi
    CMP, JEDN, ED, GEN = 'ß=?%' #znak jednakosti i posebni operatori za cvjetne tipove
    PLUS, MINUS, PUTA, ZAREZ = '+-*,' #klasicni aritmeticki operatori za numericki tip
    OO, OZ, VO, VZ, UO, UZ = '(){}[]' #npr. OO = obla otvorena
    SQLINSERT = '->' #unos u bazu podataka
    SQLFETCH = '<-' #dohvacanje iz baze podataka
    PROGRAM = 'program'
    class LAT_NAZ(Token): #latinski naziv cvijeta, prva rijec pocinje velikim slovom, druga malim
        def vrijednost(self, mem, unutar): return self.sadržaj
    class BROJ(Token):
        def vrijednost(self, mem, unutar): return int(self.sadržaj)
    class NUMVAR(Token): #numericka varijabla/fja
        def vrijednost(self, mem, unutar): return mem[self]
    class FLOWERVAR(Token): #cvjetna varijabla (vrijednost je cvjetna formula, sekvenca dna ili latinski naziv)/fja
        def vrijednost(self, mem, unutar): return mem[self]
    class FLOWERF(Token): #cvjetna formula
        def vrijednost(self, mem, unutar): return self.sadržaj
    class GENSEKV(Token): #sekvenca gena
        def vrijednost(self, mem, unutar): return self.sadržaj
    class DAT(Token): #ime datoteke
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
        elif znak in {'{', '}', '(', ')'}:
            yield lex.literal(T)
        elif znak.isupper(): #latinski naziv - prva riječ velikim, druga malim slovom
            lex * str.isalpha
            if lex >= " ":
                znak = next(lex)
                if znak.isupper():
                    raise lex.greška('očekivano malo slovo')
                else:
                    lex * str.isalpha
                yield lex.literal_ili(T.LAT_NAZ)
        elif znak == '€':   #cvjetna varijabla/fja
            lex * str.isalnum
            yield lex.literal_ili(T.FLOWERVAR)
        elif znak == '$':   #numericka varijabla/fja
            lex * str.isalnum
            yield lex.literal_ili(T.NUMVAR)
        elif znak == '#': #jednolinijski komentar
            lex - "\n"
            lex.zanemari()
        elif znak == '[': #cvjetna formula
            flag = 0
            if poc1 := lex >= 'B': #bracts (optional)
                if not lex > 't':
                    ffControl(lex)
                else:
                    poc = lex >> 't'
                    ffControl(lex)
                    flag = 1
            if flag == 0:
                if lex >= 'B': #bracteoles (optional)
                    poc = lex >> 't'
                    ffControl(lex)
            if lex > {'P', 'C'}: #tepals
                if lex >= 'C':
                    lex >> 'a'
                    lex >> 'C'
                    poc = lex >> 'o'
                    ffControl(lex)
                else:
                    poc = lex >> 'P'
                    ffControl(lex)
                poc = lex >> 'A' #stamens
                ffControl(lex)
                poc = lex >> 'G' #carpels
                ffControl(lex)
                if poc1 := lex >= {'O', 'V'}: #ovules (optional)
                    ffControl(lex)
                    lex >> ']'
                    yield lex.token(T.FLOWERF)
                else:
                    lex >> ']'
                    yield lex.token(T.FLOWERF)
            elif lex > {'K', 'C'}: #sepals and petals
                if lex >= 'C':
                    poc = lex >> 'a'
                    ffControl(lex)
                else:
                    poc = lex >> 'K'
                    ffControl(lex)
                poc = lex >> 'C'
                if poc1 := lex >= 'o':
                    ffControl(lex)
                else:
                    ffControl(lex)
                poc = lex >> 'A' #stamens
                ffControl(lex)
                poc = lex >> 'G' #carpels
                ffControl(lex)
                if poc1 := lex >= {'O', 'V'}: #ovules (optional)
                    ffControl(lex)
                    lex >> ']'
                    yield lex.token(T.FLOWERF)
                else:
                    lex >> ']'
                    yield lex.token(T.FLOWERF)
            else: #lijepi ispis uputa/greške
                string = "First formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tTepals: 'P' or 'CaCo'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
                string += "Second formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tSepals and petals: 'K' or 'Ca' and then 'C' or 'Co'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
                string += "Note that each label must be followed by a number between 1 and 12 or by the symbol '>' which means 'more than 12'"
                raise LeksičkaGreška("Neispravno formulirana cvjetna formula. Proučite sljedeće upute za ispravnu formulaciju:\n"+string)
        elif znak == '-': #sqlinsert
            if lex >= '>':
                yield lex.token(T.SQLINSERT)
            else:
                yield lex.token(T.MINUS)
        elif znak == '<': #sqlfetch
            lex >= '-'
            yield lex.token(T.SQLFETCH)
        elif znak == '"': #ime datoteke
            lex - '"'
            yield lex.token(T.DAT)
        elif znak == '=': #znak jednakosti
            yield lex.token(T.JEDN)
        elif znak == '%': #sekvence gena
            while lex > {'A', 'C', 'T', 'G'}:
                if lex > 'A':
                    lex >> 'A'
                elif lex > 'C':
                    lex >> 'C'
                elif lex > 'T':
                    lex >> 'T'
                elif lex > 'G':
                    lex >> 'G'
                else:
                    raise LeksičkaGreška("U genu se nalazi nepostojeća nukleobaza. Postojeće nukleobaze su A, C, T i G.")
            yield lex.token(T.GENSEKV)
        else: #preostalo ili alias ili literal
            lex * str.isalpha
            if lex.sadržaj == "info":
                yield lex.token(T.INFO)
            elif lex.sadržaj == "cmp":
                yield lex.token(T.CMP)
            elif lex.sadržaj == "ed":
                yield lex.token(T.ED)
            elif lex.sadržaj == "unesi":
                yield lex.token(T.SQLINSERT)
            elif lex.sadržaj == "dohvati":
                yield lex.token(T.SQLFETCH)
            else:
                yield lex.literal(T)

### BKG (ne sasvim - zbog minimalnog konteksta)
# program -> funkcija | funkcija program
# funkcija -> NR? (FLOWERVAR|NUMVAR) OO parametri? OZ NR? VO NR? naredbe NR? VZ NR? |
#              NR? PROGRAM OO OZ NR? VO NR? naredbe NR? VZ NR?
# parametri -> ime | parametri ZAREZ ime
# ime -> NUMVAR | FLOWERVAR
# naredba -> DATW OO DAT ZAREZ (cvjetni_clan|aritm) |
#           NUMVAR numerickaNaredba | FLOWERVAR cvjetnaNaredba | INFO cvjetni_clan
#           blok | RET povratna | RET | SQLINSERT LAT_NAZ SQLINSERT FLOWERF SQLINSERT GENSEKV |
#           SQLFETCH cvjetni_član | (LAT_NAZ|FLOWERF|GENSEKV) (closest|gen_dist) | BROJ petlja
# naredbe -> naredba | naredbe NR naredba
# numerickaNaredba -> pridružiIzDat  | pridružiN | petlja | poziv
# cvjetnaNaredba -> pridružiIzDat | pridružiF | ED gen_dist | CMP closest | CMP | poziv
# pridružiIzDat ->  JEDNAKO DATREAD OO DAT OZ 
# pridružiN -> JEDNAKO aritm
# pridružiF -> JEDNAKO cvjetna_aritm
# petlja -> NR? VO NR? naredbe NR? VZ
# poziv -> OO OZ | OO argumenti OZ
# argumenti -> argument | argumenti ZAREZ argument
# argument -> aritm |! cvjetna_aritm  [!KONTEKST]
# gen_dist -> cvjetni_clan |  gen_dist ED cvjetni_clan
# closest -> cvjetni_clan |  closest CMP cvjetni_clan
# cvjetna_aritm -> cvjetni_clan ED gen_dist | cvjetni_clan
# cvjetni_clan -> cvjetni_faktor CMP closest | cvjetni_faktor
# cvjetni_faktor -> FLOWERF | GENSEKV | LAT_NAZ | FLOWERVAR | FLOWERVAR poziv
# aritm -> član | aritm PLUS član | aritm MINUS član
# član -> faktor | član ZVJEZDICA faktor
# faktor -> BROJ | NUMVAR | NUMVAR poziv | OO aritm OZ | MINUS faktor
# povratna -> (aritm|BROJ) |! (cvjetna_aritm|FLOWERF|GENSEKV|LAT_NAZ) [!KONTEKST]

### Parser
class P(Parser):
    def program(p) -> 'Memorija':
        p.funkcije = Memorija(redefinicija=False)
        while not p > KRAJ:
            funkcija = p.funkcija()
            p.funkcije[funkcija.ime] = funkcija
        return p.funkcije

    def funkcija(p) -> 'Funkcija':
        p >= T.NR
        if name := p >= T.FLOWERVAR:
            p.tipf = '€'
            p.imef = name
        elif name := p >= T.NUMVAR:
            p.tipf = '$'
            p.imef = name
        elif name := p >= T.PROGRAM:
            p.tipf = '!'
            p.imef = name
        p.parametrif = p.parametri()
        atributi = p.imef, p.parametrif
        return Funkcija(*atributi, p.naredba())

    def ime(p) -> 'NUMVAR|FLOWERVAR':
        return p >> {T.NUMVAR, T.FLOWERVAR}

    def parametri(p) -> 'ime*':
        p >> T.OO
        if p >= T.OZ: return []
        param = [p.ime()]
        while p >= T.ZAREZ:
            param.append(p.ime())
        p >> T.OZ
        return param

    def naredba(p) -> 'petlja|blok|Vrati|Pridruživanje|UpisiUDat|PridruziIzDatF|PridruziIzDatN|Poziv|Insert|Fetch|gen_dist|closest|Info':
        if p >= T.DATW:#upisivanje u datoteku ovisno o tipu narednog izraza
            p >> T.OO
            dat = p >> T.DAT
            p >> T.ZAREZ
            if p > {T.BROJ, T.NUMVAR}:
                unos = p.aritm()
                p >> T.OZ
                return UpisiUDat(dat, unos)
            elif p > {T.GENSEKV, T.LAT_NAZ, T.FLOWERF, T.FLOWERVAR}:
                unos = p.cvjetni_član()
                p >> T.OZ
                return UpisiUDat(dat, unos)
            else:
                return SintaksnaGreška("U datoteku se mogu upisivati samo cvjetni ili numerički tipovi podataka.")
        elif p > T.NUMVAR: #numeričkoj varijabli se može:
            ime = p.ime()
            if p >= T.JEDN:
                if p >= T.DATREAD: #ili pridružiti nešto iz datoteke
                    p >> T.OO
                    dat = p >> T.DAT
                    p >> T.OZ
                    return PridruziIzDatN(ime, dat)
                else: #ili pridružiti neki brojčani tip (rezultat poziva fje, aritmetički izraz, broj)
                    return Pridruživanje(ime, p.tipa(ime))
            elif p > T.VO: #ili nakon nje slijedi petlja
                return p.petlja(ime)
            else: #mora biti poziv funkcije
                if ime in p.funkcije:
                    funkcija = p.funkcije[ime]
                    return Poziv(funkcija, p.argumenti(funkcija.parametri))
                elif ime == p.imef:
                    return Poziv(nenavedeno, p.argumenti(p.parametrif))
                else:
                    return ime #ili cvjetna varijabla
        elif p > T.VO: #u prethodnom smo slučaju riješili slučaj vitice za petlju pa je
            return p.blok() #jedino što preostaje blok
        elif p >= T.RET: #fja moze vraćati:
            if p > T.NUMVAR: #vrijednost numeričke varijable
                return Vrati(p.tipa(p.imef))
            elif p > T.FLOWERVAR: #vrijednost cvjetne varijable
                return Vrati(p.tipa(p.imef))
            elif c := p >= {T.FLOWERF, T.GENSEKV, T.LAT_NAZ}: #nešto cvjetno
                if p.tipf == '€':
                    return Vrati(c)
                else:
                    raise SintaksnaGreška("Neispravna povratna vrijednost")
            elif d := p >= T.BROJ: #broj
                if p.tipf == '$':
                    return Vrati(d)
                else:
                    raise SintaksnaGreška("Neispravna povratna vrijednost")
            else: #ništa
                return Vrati(nenavedeno)
        elif p >= T.SQLINSERT: #pri ubacivanju nužno navesti sve 3 vrijednosti
            prvi = p >> T.LAT_NAZ
            p >> T.SQLINSERT
            drugi = p >> T.FLOWERF
            p >> T.SQLINSERT
            treci = p >> T.GENSEKV
            return Insert(prvi, drugi, treci)
        elif p >= T.SQLFETCH: #pri dohvatu dovoljno navesti jedan od 3 identifikatora
            return Fetch(p.cvjetni_član())
        elif p > T.FLOWERVAR:
            ime = p.ime()
            if p >= T.JEDN: #cvjetnoj varijabli se može pridružiti:
                if p >= T.DATREAD: #nešto iz datoteke
                    p >> T.OO
                    dat = p >> T.DAT
                    p >> T.OZ
                    return PridruziIzDatF(ime,dat)
                else: #ili rezultat poziva fje
                    return Pridruživanje(ime, p.tipa(ime))
            elif p > T.ED: #inače nakon cvjetne varijable slijedi ili operator ED
                return p.gen_dist(ime)
            elif p > T.CMP: #ili operator CMP
                return p.closest(ime)
            else: #mora biti poziv funkcije
                if ime in p.funkcije:
                    funkcija = p.funkcije[ime]
                    return Poziv(funkcija, p.argumenti(funkcija.parametri))
                elif ime == p.imef:
                    return Poziv(nenavedeno, p.argumenti(p.parametrif))
                else:
                    return ime #ili cvjetna varijabla
        elif p > T.BROJ: #jedini preostali slučaj kad možemo naići na broj je ako on prethodi petlji
            return p.petlja(p >> T.BROJ) #ostale smo slučajeve riješili kod NUMVAR
        elif p >= T.INFO:
            return Info(p.cvjetni_član())
        else:
            cvijet = p >> {T.LAT_NAZ, T.GENSEKV, T.FLOWERF}
            if p > T.ED:
                return p.gen_dist(cvijet)
            else:
                return p.closest(cvijet)

    def gen_dist(p, first) -> 'Distance': #operator ED
        flowers = [first]
        while p >= T.ED:
            if p > T.FLOWERVAR:
                flowers.append(p.ime())
            else:
                flowers.append(p.cvjetni_član())
        return Distance(flowers)

    def closest(p, first) -> 'Closest': #operator CMP
        flowers = [first]
        while p >= T.CMP:
            if p > T.FLOWERVAR:
                flowers.append(p.ime())
            elif t := p >= {T.FLOWERF, T.GENSEKV, T.LAT_NAZ}:
                flowers.append(t)
            else: #ako je T.CMP zadnji onda se u listi nalazi samo pocetna biljka koju cemo usporedivati s bazom podataka
                return Closest(flowers)
        return Closest(flowers)

    def tipa(p, ime) -> 'aritm|cvjetna_aritm': #određuje tip s kojim dalje radimo (numerički ili cvjetni)
        if ime ^ T.NUMVAR: return p.aritm()
        elif ime ^ T.FLOWERVAR: return p.cvjetna_aritm()
        else: assert False, f'Nepoznat tip od {ime}'

    def petlja(p, kolikoPuta) -> 'Petlja': #petlja (moze, a ne mora biti viselinijska)
        p >= T.NR
        p >> T.VO
        p >= T.NR
        izvrsiti=[p.naredba()]
        while p >= T.NR and not p > T.VZ:
            izvrsiti.append(p.naredba())
        p >> T.VZ
        return Petlja(kolikoPuta, izvrsiti)

    def blok(p) -> 'Blok|naredba': #blok naredbi unutar vitica
        p >= T.NR
        p >> T.VO
        p >= T.NR
        if p >= T.VZ: return Blok([])
        n = [p.naredba()]
        while p >= T.NR and not p > T.VZ:
            n.append(p.naredba())
        p >> T.VZ
        p >= T.NR
        return Blok.ili_samo(n)

    def argumenti(p, parametri) -> 'tipa*': #argumenti fja
        arg = []
        p >> T.OO
        for i, parametar in enumerate(parametri):
            if i:
                p >> T.ZAREZ
            tip = p.tipa(parametar)
            arg.append(tip)
        p >> T.OZ
        return arg

    def cvjetna_aritm(p) -> 'gen_dist|cvjetni_član': #aritmetičke operacije za cvijeće (nema prioriteta), ali se ne mogu miješati
        cilj = p.cvjetni_član()
        if p > T.ED:
            return(p.gen_dist(cilj))
        else:
            return cilj

    def cvjetni_član(p) -> 'cvjetni_faktor|closest':
        cilj1 = p.cvjetni_faktor()
        if p > T.CMP:
            return(p.closest(cilj1))
        else:
            return cilj1

    def cvjetni_faktor(p) -> 'Poziv|FLOWERVAR|FLOWERF|GENSEKV|LAT_NAZ': #članovi aritmetičkih operacija za cvijeće mogu biti
        if call := p >= T.FLOWERVAR: #ili rezultat poziva cvjetne funkcije
            if call in p.funkcije:
                funkcija = p.funkcije[call]
                return Poziv(funkcija, p.argumenti(funkcija.parametri))
            elif call == p.imef:
                return Poziv(nenavedeno, p.argumenti(p.parametrif))
            else:
                return call #ili cvjetna varijabla
        else: #ili latinski naziv ili sekvenca gena ili cvjetna formula
            return p >> {T.FLOWERF, T.GENSEKV, T.LAT_NAZ}

    def aritm(p) -> 'Zbroj|član':
        članovi = [p.član()]
        while ...:
            if p >= T.PLUS:
                članovi.append(p.član())
            elif p >= T.MINUS:
                članovi.append(Suprotan(p.član()))
            else:
                return Zbroj.ili_samo(članovi)

    def član(p) -> 'Umnožak|faktor':
        faktori = [p.faktor()]
        while p >= T.PUTA:
            faktori.append(p.faktor())
        return Umnožak.ili_samo(faktori)

    def faktor(p) -> 'Suprotan|Poziv|aritm|BROJ':
        if p >= T.MINUS:
            return Suprotan(p.faktor())
        elif call := p >= T.NUMVAR:
            if call in p.funkcije:
                funkcija = p.funkcije[call]
                return Poziv(funkcija, p.argumenti(funkcija.parametri))
            elif call == p.imef:
                return Poziv(nenavedeno, p.argumenti(p.parametrif))
            else:
                return call
        elif p >= T.OO:
            u_zagradi = p.aritm()
            p >> T.OZ
            return u_zagradi
        else:
            return p >> T.BROJ

def izvrši(funkcije, *argv):
    funkcije['program'].pozovi(argv)

### AST
# Funkcija: ime: NUMVAR|FLOWERVAR|PROGRAM parametri:[NUMVAR|FLOWERVAR] tijelo:naredba
# naredba: Petlja: kolikoPuta:NUMVAR|BROJ tijelo:[naredba]
#          Blok: naredbe:[naredba]
#          Pridruživanje: ime:NUMVAR|FLOWERVAR pridruženo:izraz
#          UpisiUDat: imeDat:DAT unos:BROJ|GENSEKV|LAT_NAZ|FLOWERF|FLOWERVAR|NUMVAR
#          PridruziIzDatN: ime:NUMVAR imeDat:DAT
#          PridruziIzDatF: ime:FLOWERVAR imeDat:DAT
#          Insert: prvi:LAT_NAZ drugi:FLOWERF treci:GENSEKV
#          Fetch: flower:FLOWERVAR|LAT_NAZ|GENSEKV|FLOWERF
#          Closest: flowers:[LAT_NAZ|GENSEKV|FLOWERF|FLOWERVAR]
#          Distance: flowers:[LAT_NAZ|GENSEKV|FLOWERF|FLOWERVAR]
#          Info: flower:FLOWERVAR|LAT_NAZ|GENSEKV|FLOWERF
#          Vrati: što:izraz
# izraz: aritm: Zbroj: pribrojnici:[aritm]
#               Suprotan: od:aritm
#               Umnožak: faktori:[aritm]
#               Poziv: funkcija:Funkcija? argumenti:[izraz]
#        cvjetna_aritm: Poziv: funkcija:Funkcija? argumenti:[izraz]
#                       Closest: flowers:[LAT_NAZ|GENSEKV|FLOWERF|FLOWERVAR]
#                   Distance: flowers:[LAT_NAZ|GENSEKV|FLOWERF|FLOWERVAR]

class UpisiUDat(AST):
    """Upisivanje u datoteku; svaki put se ono sto je prije pisalo u datoteci prebrise"""
    imeDat: 'DAT'
    unos: 'BROJ|GENSEKV|LAT_NAZ|FLOWERF|FLOWERVAR|NUMVAR'
    def izvrši(self, mem, unutar):
        cistoIme = self.imeDat.vrijednost(mem, unutar)
        novoIme = cistoIme[1:len(cistoIme) - 1] #uklonjeni navodnici iz imena kako bi se mogao izvrsiti open
        f = open(novoIme, 'w+')
        string = str(self.unos.vrijednost(mem, unutar))
        provjeraNavodnika = string.find('"')
        if provjeraNavodnika != -1:
            string = string[1:len(string)]
            drugiNavodnik = string.find('"')
            if drugiNavodnik != -1:
                string = string[0:len(string)-1]
        f.write(string)
        f.close()
#pomocna funkcija koja sluzi za provjeru ispravnosti cvjetne formule prilikom citanja iz datoteke
#vraca broj mjesta koje zauzima broj iz svakog dijela biljke
def ffnumbers(p, s):
    if s[p] == '>':
        return 1
    elif s[p] == '1':
        if s[p+1] in {'3', '4', '5', '6', '7', '8', '9'}:
            string = "First formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tTepals: 'P' or 'CaCo'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
            string += "Second formulation option:\n\tBracts(optional): 'B'\n\tBracteoles(optional): 'Bt'\n\tSepals and petals: 'K' or 'Ca' and then 'C' or 'Co'\n\tStamens: 'A'\n\tCarpels: 'G'\n\tOvules(optional): 'V' or 'O'\n"
            string += "Note that each label must be followed by a number between 1 and 12 or by the symbol '>' which means 'more than 12'"
            raise Greška("Neispravno formulirana cvjetna formula. Proučite sljedeće upute za ispravnu formulaciju:\n"+string)
        elif s[p+1] in {'0', '1', '2'}:
            return 2
        else:
            raise Greška("Neispravno unesen broj dijelova biljke u cvjetnu formulu.")
    elif s[p] in {'2', '3', '4', '5', '6', '7', '8', '9'}:
        return 1
    else:
        return 0

class PridruziIzDatN(AST):
    """Pridruzivanje procitanog iz datoteke numerickoj varijabli"""
    ime: 'NUMVAR'
    imeDat: 'DAT'
    def izvrši(self,mem,unutar):
        cistoIme = self.imeDat.vrijednost(mem, unutar)
        novoIme = cistoIme[1:len(cistoIme) - 1] #uklonjeni navodnici iz imena kako bi se mogao izvrsiti open
        f = open(novoIme, 'r')
        procitaj = f.read()

        #u datoteci moze pisati bilo sto, pa je potrebno provjeriti pridruzujemo li ispravne vrijednosti
        if procitaj.isnumeric():
            mem[self.ime]=procitaj
        else:
            raise Greška("Varijabla je numerička, unesite broj.")

        f.close()

class PridruziIzDatF(AST):
    """Pridruzivanje procitanog iz datoteke cvjetnoj varijabli"""
    ime: 'FLOWERVAR'
    imeDat: 'DAT'
    def izvrši(self,mem,unutar):
        cistoIme = self.imeDat.vrijednost(mem, unutar)
        novoIme = cistoIme[1:len(cistoIme) - 1] #uklonjeni navodnici iz imena kako bi se mogao izvrsiti open
        f = open(novoIme, 'r')
        procitaj = f.read()

        #u datoteci moze pisati bilo sto, pa je potrebno provjeriti pridruzujemo li ispravne vrijednosti
        if procitaj.isalpha() or " " in procitaj: #potrebno je provjeriti je li latinski naziv
            lista=procitaj.split(" ")
            if(len(lista)==2) and procitaj[0].isupper():
                t=procitaj.find(" ")
                if procitaj[t+1].isupper():
                    raise Greška("Očekivano malo slovo drugoj riječi u latinskom nazivu biljke.")
                else:
                    mem[self.ime]=procitaj
            else:
                raise Greška('Neispravno unesen latinski naziv biljke')
        elif procitaj[0] == "%": #potrebno provjerit je li genetska sekvenca ispravno unesena
            for i in procitaj[1:]:
                if i not in {"A", "G", "C", "T"}:
                    raise Greška("U genu se nalazi nepostojeća nukleobaza. Postojeće nukleobaze su A, C, T i G.")
            mem[self.ime]=procitaj

        elif procitaj[0] == "[" and procitaj[-1] == "]": #potrebno provjeriti je li cvjetna formula ispravno zadana
            flag = 0
            i = 1
            if procitaj[i] == 'B': #bracts (optional)
                i+=1
                if not  procitaj[i] == 't':
                    i+=ffnumbers(i, procitaj)+1
                else:
                    i+=ffnumbers(i+1, procitaj)+1
                    flag = 1
            if flag == 0:
                if procitaj[i] == 'B' and procitaj[i+1] == 't': #bracteoles (optional)
                    i+=2
                    i+=ffnumbers(i, procitaj)
            if procitaj[i] in {'P', 'C'}: #tepals
                if procitaj[i:i+4] == "CaCo":
                    i+=4
                    i+=ffnumbers(i, procitaj)
                else:
                    i+=ffnumbers(i+1, procitaj)+1

                if procitaj[i] == 'A': #stamens
                    i+=ffnumbers(i+1, procitaj)+1
                else:
                    raise Greška("Neispravna cvjetna formula, nedostaje A.")

                if procitaj[i] == 'G':
                    i+=ffnumbers(i+1, procitaj)+1
                else:
                    raise Greška("Neispravna cvjetna formula, nedostaje G.")

                if procitaj[i] in {'O', 'V'}: #ovules (optional)
                    i+=ffnumbers(i+1, procitaj)+1

            elif procitaj[i] in {'K', 'C'}: #sepals and petals
                if procitaj[i:i+2] == "Ca":
                    i+=ffnumbers(i+2, procitaj)+2
                else:
                    i+=ffnumbers(i+1, procitaj)+1

                if procitaj[i] == 'C':
                    i+=1
                    if procitaj[i] == 'o':
                        i+=ffnumbers(i+1, procitaj)+1
                    else:
                        i+=ffnumbers(i, procitaj)

                if procitaj[i] == 'A': #stamens
                    i+=ffnumbers(i+1, procitaj)+1
                else:
                    raise Greška("Neispravna cvjetna formula, nedostaje A.")

                if procitaj[i] == 'G':
                    i+=ffnumbers(i+1, procitaj)+1
                else:
                    raise Greška("Neispravna cvjetna formula, nedostaje G.")

                if procitaj[i] in {'O', 'V'}: #ovules (optional)
                    i+=ffnumbers(i+1, procitaj)+1

            mem[self.ime]=procitaj
        else:
            raise Greška("Podatak u datoteci nije moguće zapisati u cvjetnu varijablu jer se tipovi ne podudaraju.")
        f.close()

#pomocna funkcija koja kao parametre prima ime stupca kojeg pretrazujemo, te podatak koji trazimo
#vraca redni broj mjesta na kojemu se podatak nalazi u tom stupcu
def pronadiBroj(imeStupca, podatak):
    broj=-1
    for tablica,log in rt.imena:
        for stupac,pristup in log:
            i=0
            if stupac==imeStupca:
                for thing in pristup.objekt.rows:
                    if thing==podatak:
                        broj=i
                        break
                    i+=1
    return broj

#pomocna funkcija koja kao parametre prima ime stupca kojeg pretrazujemo, redni broj mjesta podatka
#vraca podatak koji se nalazi na trazenom mjestu u zadanom stupcu
def vratiPodatak(imeStupca, broj):
    vrati=""
    for tablica,log in rt.imena:
        for stupac,pristup in log:
            if stupac==imeStupca:
                brojac=0
                for thing in pristup.objekt.rows:
                    if(brojac==broj):
                        vrati=thing
                        break
                    brojac+=1
    return vrati

class Insert(AST):
    """Unos podataka u bazu"""
    prvi: 'LAT_NAZ'
    drugi: 'FLOWERF'
    treci: 'GENSEKV'
    def izvrši(self, mem, unutar):
        #prvo provjeravamo nalazi li se podatak koji se pokusava unjeti u bazi
        provjera=-1
        provjera=pronadiBroj("LN",self.prvi.vrijednost(mem,unutar))
        #ako se podatak ne nalazi u bazi onda ga unosimo
        if(provjera==-1): #podatak se ne nalazi u tablici, stoga ga sada unosimo
            for tablica,log in rt.imena:
                for stupac,pristup in log:
                    if stupac=="LN":
                        pristup.objekt.rows.append(self.prvi.vrijednost(mem,unutar))
                    elif stupac=="FF":
                        pristup.objekt.rows.append(self.drugi.vrijednost(mem,unutar))
                    elif stupac=="GS":
                        pristup.objekt.rows.append(self.treci.vrijednost(mem,unutar))

class Fetch(AST):
    """Na temelju zadanog cvjetnog podatka dohvaca sve podatke pripadne biljke iz tablice"""
    flower: 'FLOWERVAR|LAT_NAZ|GENSEKV|FLOWERF'
    def izvrši(self,mem,unutar):
        ln=""
        ff=""
        gs=""
        #potrebno je odrediti o kojoj vrsti podatka je rijec
        if " " in self.flower.vrijednost(mem,unutar): #korisnik je unio latinski naziv
            ln=self.flower.vrijednost(mem,unutar)
            broj=-1
            #dohvacamo redni broj elementa te u odgovarajuce varijable spremamo preostale podatke, analogno u ostalim slucajevima
            broj=pronadiBroj("LN",self.flower.vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flower.vrijednost(mem,unutar) + ' u tablici')
            ff=vratiPodatak("FF",broj)
            gs=vratiPodatak("GS",broj)
        elif "[" in self.flower.vrijednost(mem,unutar): #korisnik je unio cvijetnu fomulu
            ff=self.flower.vrijednost(mem,unutar)
            broj=-1
            broj=pronadiBroj("FF",self.flower.vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flower.vrijednost(mem,unutar) + ' u tablici')
            ln=vratiPodatak("LN",broj)
            gs=vratiPodatak("GS",broj)
        else: #korisnik je unio genetski kod
            broj=-1
            gs=self.flower.vrijednost(mem,unutar)
            broj=-1
            broj=pronadiBroj("GS",self.flower.vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flower.vrijednost(mem,unutar) + ' u tablici')
            ln=vratiPodatak("LN",broj)
            ff=vratiPodatak("FF",broj)
        print(ln+" "+ff+" "+gs) #ispis dohvacenih podataka

class Closest(AST):
    """Na temelju prvog cvjetnog podatka iz liste među ostalima pronalazi njemu genetski najbližeg"""
    flowers: '(FLOWERVAR|GENSEKV|LAT_NAZ|FLOWERF)*'

    def vrijednost(self,mem,unutar):
        genKodovi=[] #lista genetskih kodova koje usporedujemo
        broj=-1
        #prvo trazimo redni broj i genetski kod prve (mozda i jedine) biljke u listi
        #kako je moguce unjeti latinski naziv, cvjetnu formulu ili genetsku sekvencu provjeravamo sve mogucnosti
        if " " in self.flowers[0].vrijednost(mem,unutar): #imamo latinski naziv
            broj=pronadiBroj("LN",self.flowers[0].vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flowers[0].vrijednost(mem,unutar) + ' u tablici')
            genKodovi.append(vratiPodatak("GS",broj))
        elif "[" in self.flowers[0].vrijednost(mem,unutar): #imamo cvijetnu fomulu
            broj=-1
            broj=pronadiBroj("FF", self.flowers[0].vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flowers[0].vrijednost(mem,unutar) + ' u tablici')
            genKodovi.append(vratiPodatak("GS",broj))

        else: #imamo genetski kod
            genKodovi.append(self.flowers[0].vrijednost(mem,unutar))
        if len(self.flowers)>1: #u listi se nalazi više biljaka koje medusobno usporedujemo
            for cvijet in self.flowers[1:]: #iterira od drugog (indeks 1) elementa liste
                if " " in cvijet.vrijednost(mem,unutar): #imamo latinski naziv
                    #trazimo koje po redu u stupcu je cvijet.vrijednost(mem,unutar) kako bi mogli uzeti genetski kod iz istog reda
                    broj=-1
                    broj=pronadiBroj("LN",cvijet.vrijednost(mem,unutar))
                    if broj==-1:
                        raise GreškaIzvođenja('Ne postoji objekt ' + cvijet.vrijednost(mem,unutar) + ' u tablici')
                    genKodovi.append(vratiPodatak("GS",broj))

                elif "[" in cvijet.vrijednost(mem,unutar): #imamo cvijetnu fomulu
                    broj=-1
                    broj=pronadiBroj("FF",cvijet.vrijednost(mem,unutar))
                    if broj==-1:
                        raise GreškaIzvođenja('Ne postoji objekt ' + cvijet.vrijednost(mem,unutar) + ' u tablici')
                    genKodovi.append(vratiPodatak("GS",broj))

                else: #imamo genetski kod
                    genKodovi.append(cvijet.vrijednost(mem,unutar))
        elif len(self.flowers)==1: #u listi se nalazi samo jedna biljka koju usporedujemo sa svim biljkama baze
        #u listu genetski kodovi stavljamo genetske kodove svih biljaka iz baze s kojima usporedujem promatranu biljku
            for tablica,log in rt.imena:
                for stupac,pristup in log:
                    if stupac=="GS":
                        brojac=0
                        for thing in pristup.objekt.rows:
                            if(brojac!=broj):
                                genKodovi.append(thing)
                            brojac+=1
        l=len(min(genKodovi,key=len)) #duljina najkraceg genetskog koda
        maks=0 #max broj gena koji se podudaraju
        cvijet2=""
        for j in range (1,len(genKodovi)): #ne usporedujemo cvijet sam sa sobom
            brojac=0
            for k in range(0,l):
                if(genKodovi[0][k]==genKodovi[j][k]): #usporedujemo gen po gen
                    brojac+=1
                    if(brojac>maks):
                        maks=brojac
                        br=pronadiBroj("GS",genKodovi[j])
                        cvijet2=vratiPodatak("LN",br)
        return cvijet2 #vraćamo biljku najblizu promatranoj

class Distance(AST):
    """U listi cvjetnih podataka pronalazi dvije genetski najbliže biljke"""
    flowers: '(FLOWERVAR|GENSEKV|LAT_NAZ|FLOWERF)*'
    def izvrši(self,mem,unutar):
        genKodovi=[] #lista genetskih kodova koje usporedujemo
        for cvijet in self.flowers:
            #kako je moguce unjeti latinski naziv, cvjetnu formulu ili genetsku sekvencu provjeravamo sve mogucnosti
            if " " in cvijet.vrijednost(mem,unutar): #imamo latinski naziv
                broj=-1
                broj=pronadiBroj("LN", cvijet.vrijednost(mem,unutar))
                if broj==-1:
                    raise GreškaIzvođenja('Ne postoji objekt ' + cvijet.vrijednost(mem,unutar) + ' u tablici')
                genKodovi.append(vratiPodatak("GS",broj))
            elif "[" in cvijet.vrijednost(mem,unutar): #imamo cvijetnu fomulu
                broj=-1
                broj=pronadiBroj("FF", cvijet.vrijednost(mem,unutar))
                if broj==-1:
                    raise GreškaIzvođenja('Ne postoji objekt ' + cvijet.vrijednost(mem,unutar) + ' u tablici')
                genKodovi.append(vratiPodatak("GS",broj))

            else: #imamo genetski kod
                genKodovi.append(cvijet.vrijednost(mem,unutar))
        l=len(min(genKodovi,key=len)) #duljina najkraceg genetskog koda
        maks=0 #max broj gena koji se podudaraju
        cvijet1=""
        cvijet2=""
        for i in range(len(self.flowers)):
            for j in range(i+1,len(self.flowers)): #ne usporedujemo cvijet sam sa sobom
                brojac=0
                for k in range(0,l):
                    if(genKodovi[i][k]==genKodovi[j][k]):
                        brojac+=1
                        if(brojac>maks):
                            maks=brojac
                            cvijet1=self.flowers[i]
                            cvijet2=self.flowers[j]
        print(cvijet1.vrijednost(mem,unutar)+" "+cvijet2.vrijednost(mem,unutar)) #ispisujemo koje dvije biljke su genetski najblize

class Info(AST):
    """Na temelju danog cvjetnog podatka ispisuje informacije o odgovarajućoj biljci"""
    flower: 'FLOWERVAR|LAT_NAZ|GENSEKV|FLOWERF'
    def izvrši(self, mem, unutar):
        ff=""
        #trazimo genetski kod promatrane biljke
        #kako je moguce unjeti latinski naziv, cvjetnu formulu ili genetsku sekvencu provjeravamo sve mogucnosti
        if " " in self.flower.vrijednost(mem,unutar): #imamo latinski naziv
            broj=-1
            broj=pronadiBroj("LN", self.flower.vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flower.vrijednost(mem,unutar) + ' u tablici')
            ff=vratiPodatak("FF",broj)

        else: #imamo genetski kod
            broj=-1
            broj=pronadiBroj("GS", self.flower.vrijednost(mem,unutar))
            if broj==-1:
                raise GreškaIzvođenja('Ne postoji objekt ' + self.flower.vrijednost(mem,unutar) + ' u tablici')
            ff=vratiPodatak("FF",broj)

        #provjera od kojih se dijelova sastoji biljka te njihov ispis
        p=ff.find("t")
        if(p == -1):
            print("Biljka ne sadrži bracteole.") #nisam uspjela pronaci prijevod na hrvatski
        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više bracteola.")
                else: print("Biljka sadrži ", ff[p+1], " bracteola.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jedan bracteol.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " bracteola.")

        p=ff.find("B")
        if(p == -1):
            print("Biljka ne sadrži zalistke.")
        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više zalistaka.")
                else: print("Biljka sadrži ", ff[p+1], " zalistaka.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jedan zalistak.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " zalistaka.")

        p=ff.find("A")
        if(p == -1):
            print("Biljka ne sadrži prašnike.")
        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više prašnika.")
                else: print("Biljka sadrži ", ff[p+1], " prašnika.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jedan prašnik.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " prašnika.")

        p=ff.find("G")
        if(p == -1):
            print("Biljka ne sadrži pestić.") #sta god da to je
        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više pestića.")
                else: print("Biljka sadrži ", ff[p+1], " pestića.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jedan pestića.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " pestića.")

        p=ff.find("V")
        if(p == -1):
            t=ff.find("O")
            if(t == -1):
                print("Biljka ne sadrži cvijetne plodnice.")
            else:
                if not ff[t+2].isdigit():
                    if ff[t+1] == ">": print("Biljka sadrži 12 ili više cvijetnih plodnica.")
                    else: print("Biljka sadrži ", ff[t+1], " cvijetnih plodnica.")
                else:
                    if not ff[t+1].isdigit(): print("Biljka sadrži jednu cvjetnu plodnicu.")
                    else: print("Biljka sadrži ", ff[t+1]+ff[t+2], " cvjetnih plodnica.")
        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više cvijetnih plodnica.")
                else: print("Biljka sadrži ", ff[p+1], " cvijetnih plodnica.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jednu cvjetnu plodnicu.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " cvjetnih plodnica.")

        p=ff.find("P")
        if(p == -1):
            if "CaCo" in ff: #U formuli se moze pisati CaCo umjesto P
                t=ff.find("o")
                if(t == -1):
                    print("Biljka ne sadrži vanjske latice.")
                else:
                    if not ff[t+2].isdigit():
                        if ff[t+1] == ">": print("Biljka sadrži 12 ili više vanjskih latica.")
                        else: print("Biljka sadrži ", ff[t+1], " vanjskih latica.")
                    else:
                        if not ff[t+1].isdigit(): print("Biljka sadrži jednu vanjsku laticu.")
                        else: print("Biljka sadrži ", ff[t+1]+ff[t+2], " vanjskih latica.")

            else:
                t=ff.find("K")
                if(t == -1):
                    if "Ca" in ff: #u formuli se moze pisati Ca umjesto K
                        l=ff.find("a")
                    if(l == -1):
                        print("Biljka ne sadrži čašku.")
                    else:
                        if not ff[l+2].isdigit():
                            if ff[l+1] == ">": print("Biljka sadrži 12 ili više čaški.")
                            else: print("Biljka sadrži ", ff[l+1], " čaški.")
                        else:
                            if not ff[l+1].isdigit(): print("Biljka sadrži jednu čašku.")
                            else: print("Biljka sadrži ", ff[l+1]+ff[l+2], " čaški.")
                else:
                    if not ff[t+2].isdigit():
                        if ff[t+1] == ">": print("Biljka sadrži 12 ili više čaški.") #čaški ili čašci? nisam pismena -Dorotea
                        else: print("Biljka sadrži ", ff[t+1], " čaški.")
                    else:
                        if not ff[t+1].isdigit(): print("Biljka sadrži jednu čašku.")
                        else: print("Biljka sadrži ", ff[t+1]+ff[t+2], " čaški.")

                t=ff.find("o") # moze pisati Co ili C, prvo provjeravamo pise li Co
                if(t == -1):
                    l=ff.find("C")
                    if(l == -1):
                        print("Biljka ne sadrži latice.")
                    else:
                        if not ff[l+2].isdigit():
                            if ff[l+1] == ">":
                                print("Biljka sadrži 12 ili više latica.")
                                vratiti = math.inf
                            else:
                                print("Biljka sadrži ", ff[l+1], " latica.")
                                vratiti = ff[l+1]
                        else:
                            if not ff[l+1].isdigit():
                                print("Biljka sadrži jednu laticu.")
                                vratiti = 1
                            else:
                                print("Biljka sadrži ", ff[l+1]+ff[l+2], " laticu.")
                                vratiti = ff[l+1]+ff[l+2]
                else:
                    if not ff[t+2].isdigit():
                        if ff[t+1] == ">":
                            print("Biljka sadrži 12 ili više latica.")
                            vratiti = math.inf
                        else:
                            print("Biljka sadrži ", ff[t+1], " latica.")
                            vratiti = ff[l+1]
                    else:
                        if not ff[t+1].isdigit():
                            print("Biljka sadrži jednu laticu.")
                            vratiti = 1
                        else:
                            print("Biljka sadrži ", ff[t+1]+ff[t+2], " laticu.")
                            vratiti = ff[l+1]+ff[l+2]

        else:
            if not ff[p+2].isdigit():
                if ff[p+1] == ">": print("Biljka sadrži 12 ili više vanjskih latica.")
                else: print("Biljka sadrži ", ff[p+1], " vanjskih latica.")
            else:
                if not ff[p+1].isdigit(): print("Biljka sadrži jednu vanjsku laticu.")
                else: print("Biljka sadrži ", ff[p+1]+ff[p+2], " vanjskih latica.")

class Funkcija(AST):
    ime: 'FLOWERVAR|NUMVAR|PROGRAM'
    parametri: '(FLOWERVAR|NUMVAR)*'
    tijelo: 'naredba'
    def pozovi(funkcija, argumenti):
        lokalni = Memorija(zip(funkcija.parametri, argumenti))
        try: funkcija.tijelo.izvrši(mem=lokalni, unutar=funkcija)
        except Povratak as exc: return exc.preneseno
        else:
            if str(funkcija.ime)[8:len(str(funkcija.ime))-1] != "program": #main ne mora nista vratiti
                raise GreškaIzvođenja(f'{funkcija.ime} nije ništa vratila')

class Poziv(AST):
    funkcija: 'Funkcija?'
    argumenti: 'izraz*'
    def vrijednost(poziv, mem, unutar):
        pozvana = poziv.funkcija
        if pozvana is nenavedeno: pozvana = unutar  # rekurzivni poziv
        argumenti = [a.vrijednost(mem, unutar) for a in poziv.argumenti]
        return pozvana.pozovi(argumenti)

    def izvrši(poziv, mem, unutar): #za samostalne pozive (bez pridruživanja)
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
    """Naredbe unutar izvrsiti izvrše se kolikoPuta puta"""
    kolikoPuta: 'NUMVAR|BROJ'
    izvrsiti: 'naredba*'
    def izvrši(petlja, mem, unutar):
        for i in range(petlja.kolikoPuta.vrijednost(mem, unutar)):
            for naredba in petlja.izvrsiti: naredba.izvrši(mem, unutar)

class Blok(AST):
    naredbe: 'naredba*'
    def izvrši(blok, mem, unutar):
        for naredba in blok.naredbe: naredba.izvrši(mem, unutar)

class Pridruživanje(AST):
    ime: 'NUMVAR|FLOWERVAR'
    pridruženo: 'izraz'
    def izvrši(self, mem, unutar):
        mem[self.ime] = self.pridruženo.vrijednost(mem, unutar)

class Vrati(AST):
    što: 'izraz'
    def izvrši(self, mem, unutar):
        if self.što == nenavedeno: #u slucaju tzv. void funkcije
            raise Povratak(nenavedeno)
        else: #inace
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
#pomoćne klase za sql
class Stupac:
    """Specifikacija stupca u tablici."""
    def __init__(self, ime, tip, rows):
        self.ime = ime
        self.tip = tip
        self.rows = rows
class Create():
    """Naredba za ubacivanje podataka u tablicu."""
    def __init__(self, tablica, specifikacije):
        self.tablica = tablica
        self.specifikacije = specifikacije
    def razriješi(naredba):
        pristup = rt.imena[naredba.tablica] = Memorija(redefinicija=False)
        for stupac in naredba.specifikacije:
            pristup[stupac.ime] = PristupLog(stupac)
#popunjavanje tablice
rt.imena = Memorija(redefinicija=False)
nazivi = ["Rosa rubiginosa"]
nazivi.append("Rosa rugosa")
nazivi.append("Olea europaea")
nazivi.append("Aloe Barbadensis")
nazivi.append("Mammillaria mystax")
nazivi.append("Ferocactus Wislizeni")
nazivi.append("Citrus limon")
nazivi.append("Acer palmatum")
stupci = [Stupac("LN", "LAT_NAZ", nazivi)]

formule = ["[K5C5AG10]"]
formule.append("[K5C2A1G9]")
formule.append("[K4C4A2G2]")
formule.append("[OP3A3G3]")
formule.append("[K>C>A>G>]")
formule.append("[K>C>A>G11]")
formule.append("[K5C5A8G4]")
formule.append("[K5C5A8G2]")
stupci.append(Stupac("FF", "FLOWERF", formule))

geni = ["%ATGCTGACGTACGTTA"]
geni.append("%ATGACGCTGTACGTTA")
geni.append("%TAGAGAATCCGGCTGTTTTACCGTTA")
geni.append("%CCTGTTTTACCGTTATAGAGAATCCGTTTT")
geni.append("%TAGACCATGACATAGGCAATTACCGTTA")
geni.append("%AAATAGGATACCATTACCGCCGTTTT")
geni.append("%ACGTTTTCGTATTCGTTA")
geni.append("%ACGTTTTCGTATTC")
stupci.append(Stupac("GS", "GENSEKV", geni))
Create("Botanika", stupci).razriješi()
#ispis tablice
""" for tablica, log in rt.imena: #ispis sql tablice
    print('Tablica', tablica, '- stupci:')
    for stupac, pristup in log:
        print('\t', stupac, pristup)
        for thing in pristup.objekt.rows: ##prolazak po rows
            print('\t', thing) """
#prvi program
"""
proba = P('''
#komentar
$potnapot($x){
    $y = 1
    $x{
        $y = $x * $y
    }
    ret $y
#vraca x^x
}
$fakt($x){
    $y = 1
    $z = 1
    $x{
        $z = $z * $y
        $y = $y + 1
    }
    ret $z
#vraca x!
}
program(){
    $a = 6
    $a = $potnapot($a)
    datw("dat11.txt", $a)
    #pise (a^a) u dat11.txt
    €cc = Rosa rubiginosa
    ~ €cc
    #ovo ce ispisati podatke o cvijetu, tamo cemo vidjeti da ima 5 latica
    $a = 5
    datw("dat12.txt", $a)
    #pise koliko latica ima cc u dat12.txt
    datw("dat13.txt", €cc)
    #pise Rosa rubiginosa u dat13.txt
    €ccc = datread("dat13.txt")
    datw("dat14.txt", €ccc)
    #Cita i pise Rosa rubiginosa iz dat13.txt u dat14.txt
    $a = 5
    $a = $fakt($a)
    datw("dat15.txt", $a)
}
''')
"""
#drugi program
"""
proba = P('''
#komentar
program(){
->Lilium candidum->[P3A3G3]->%ACGTCACGCACATTAC
#Lilium candidum, [P3A3G3], %ACGTCACGCACATTAC unesen u bazu
<-Lilium candidum
<-Rosa rubiginosa
<-Rosa rugosa
<-Olea europaea
#ispiše podatke iz baze za biljke
€c1 = Lilium candidum
€c1 ? Rosa rubiginosa ? Rosa rugosa
#ispiše dva cvijeta iz niza s najsličnijim genima
datw("dat21.txt", €c1)
€c2 = datread("dat21.txt")
#procita iz dat21.txt i pospremi u c2
€c2 ? Rosa rubiginosa ? Rosa rugosa
#isti ispis kao prije
€c2 ? Rosa rubiginosa ? Olea europaea
<-%ACGTCACGCACATTAC
}
''')
"""
#treci program
"""
proba = P('''
#komentar
€compnw(€c){
    €c = €c cmp
    datw("dat31.txt", €c)
    ret €c
}
#zapise c u dat31.txt i ispise najslicniji njemu
program(){
->Lilium candidum->[P3A3G3]->%ACGTCACGCACATTAC
€c1 = Rosa rubiginosa
€compnw(€c1)
#sad vidimo koja je najslicnija Rosi rubiginos
€c2 = Rosa rugosa
€novi = Lilium candidum
<-Olea europaea
<-€novi
€c4 = Olea europaea
€c1 ? €c2 ? €novi ? €c4
€novi = €novi cmp
#ispise najslicniji cvijet novom cvijetu iz baze
<-Mammillaria mystax
€najslicniji = Mammillaria mystax
datw("dat32.txt", €najslicniji)
}
''')
"""
#cetvrti program
"""
proba = P('''
program(){
->Laurus nobilis->[BtP4A1G>]->%TAGAGAATCCCGCTGTAATACCGTGA
€cvijet = Laurus nobilis
€najblizi = €cvijet ß 
datw("dat.txt", €najblizi)
#vraca koja biljka je najbliza promatranoj iz baze podataka
~ €najblizi
#ispisuje podatke o toj biljci koje procita iz cvjetne formule
dohvati €najblizi
#ispisuje sve podatke iz baze koji su pohranjeni o toj biljci
datw("dat1.txt",€cvijet ß Rosa rubiginosa ß Citrus limon)
#u datoteku zapisujemo koja je od biljaka, Rosa rubiginosa ili Citrus limon, bliza promatranoj biljci
€procitaj = datread("dat1.txt")
~ €procitaj
}
''')
"""

#### otkomentirati sljedeca dva retka za testiranje programa
"""
prikaz(proba, 5)
izvrši(proba)
"""
### treba otkomentirati za unos kroz terminal
"""
ukupni = "program(){\n"
trenutni = ""
funkcije = ""
main = ""
while 1:
    ulaz = str(input())+"\n"
    trenutni += ulaz
    #par = P(ulaz)
    #par.oneByOne()
    flag = 1
    for i in range(0, len(ulaz)):
        if ulaz[i] == ";":#kraj programa
            #opcionalni printovi za pregled programa
            #print("---funkcije---")
            #print(funkcije)
            #print("---main---")
            #print(main)
            #print("---cijeli program---")
            cijeli = funkcije + ukupni + main + 'ret\n}'
            #print(cijeli)
            par = P(cijeli)
            izvrši(par)
            trenutni = ""
        elif ulaz[i] == ')' and ulaz[i + 1] == '{':#pocetak definicije funkcije
            brVitica = 1  #sluzi za provjeru imamo li jednak broj otvorenih i zatvorenih vitica (jer se unutar funkcije moze naci for petlja)
            done = 0
            while done == 0:
                print("...", end="")
                definiranje = str(input())+"\n"
                trenutni += definiranje
                for j in definiranje:
                    if j == "}":
                        brVitica = brVitica - 1
                        if brVitica == 0:
                            funkcije += trenutni
                            trenutni = ""
                            done = 1
                            flag = 0
                    elif j == '{':
                        brVitica = brVitica + 1
    if flag==1:
        if ';' not in ulaz:
            main +=ulaz
    trenutni = ""
"""