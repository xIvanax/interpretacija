# Pliz provjerite jel mislite da su BKG i AST-ovi u skladu s onim sta pise
# Ivana

* pushala sam datoteku proba.txt u kojoj mozete vidjeti sto sam tocno probavala upisati u terminal
* funkcionira isto kao pythonov shell, znaci ak se unosi funkcija ona se pamti, a ak se unosi bilo sta drugo smatra se dijelom glavnom programa
* unos ; oznacava da korisnik zeli izvršiti naredbu i nakon sto izvrsi neku naredbu moze opet izvrsavati naredbe (dakle korisnik moze u bilo kojem trenu definirati neku funkciju ili napisati naredbu, ima opciju izvršavanja naredbi jednu po jednu t.d. nakon svake upise ;, a moze i unositi proizvoljan broj naredbi)
# Žalbe
* ~~funkcija nemre primiti flowervar - popravljeno _~Ivana_~~
* ~~treba napraviti retsrikcije/provjere u ast-u Pridruživanje t.d. se numeričkoj varijabli ne može pridružiti nešto cvjetno i slično - popravljeno _~Ivana_~~
* ~~treba osmisliti kak provjeriti koji je tip podatka vratila funkcija ili čitanje iz datoteke pa opet paziti je li prikladno priduruženo NUMVAR-u ili FLOWERVAR-u - popravljeno _~Dorotea_~~
* funkcije ne mogu primiti poziv druge funkcije ili aritmeticki izraz kao argument - mozda sad mogu, treba provjeriti i napomenuti jel mogu il ne
* ~~for petlja moze imati i NUMVAR i BROJ prije { - omoguceno _~Ivana_~~
* ~~trenutno pri citanju iz sql tablice ne pazimo na mogucnost jel fali neki podatak ( ja mislim) - pazila _~Dorotea_ :)~~
* ~~ne radi pridruzivanje funkcije tipa $x =f($y) - iz nekog razloga proguta =f kao ime funkcije umjesto da zasebno proguta = i f - treba popraviti ili cemo kao dodatan uvjet u jeziku definirati "prozračnost" koda (moraju dolaziti razmaci izmedu svega) - resolved, bila je grška u lekseru _~Ivana_~~
* ~~funkcija se ne može pozvati bez da se pridruži varijabli - popravljeno _~Ivana_~~
* ~~omogucene void fje (umjesto ret nesto moze biti i samo ret) _~Ivana_~~
* ~~treba provjeriti javlja li gresku ako cvjetnoj varijabli pridruzimo broj ili poziv fje koja vraca broj i slicno
* za sada smo ostavili da je upis u datoteku takav da se stari sadrzaj brise i unosi se novi, mozda ako smislimo kako bismo citali iz datoteke u slucaju da se u datoteku samo nadopise mozemo to uskladiti
* ~~moraju li vitice bit u novom redu - pa meni se čini da ne moraju, barem nije na testiranom stvaralo probleme _~Dorotea_~~
* napraviti funkciju vrijednost za cmp
* provjeriti mozemo li kao povratnu vrijednost funkcije vratiti rezultat operatora CMP (kao sto mozemo npr rezultat operatora zbrajanja)
* ~~rastavi datread na dvoje datoteke - riješeno _~Dorotea_~~
# prije leksera
'''
Sto omogucavamo i kako:
    1) korisnik upisuje naredbu po naredbu (omoguceno pomocu while petlje na kraju koda;
        obavezni su prelasci u novi red (bez dozvoljenih višestrukih novih redova; zatvorene vitice
        moraju biti u novom retku), a kraj unošenja naredbi označava se pomoću ';' što
        zapocinje izvršavanje do sad unesenih naredbi)
        
    2) varijable (cvjetnog tipa se oznacavaju kao €varijabla, a numeričkog kao $var)
    
    3) for petlja (npr. $var{$k = $k + 1} -> znaci da se €var puta izvrši naredba $k = $k+1);
    može sadržaati i više naredbi; umjesto NUMVAR mozemo imati i obican broj 
    
    4) definicije funkcija (npr. $plus($a, $b){ret $a+$b}); fja uvijek mora završiti s ret, ali on može biti
    prazan (ne mora vratiti konkretnu vrijednost); kao argumente fja (odvojene zarezima) dozvoljavamo
    samo brojeve, cvjetne formule, sekvence gena, latinske nazive, FLOWER_VAR, NUM_VAR; za povratne vr.
    dozvoljavamo i aritmetičke izraze (numeričke)
    
    5) funkcijski poziv (od definicije se razlikuje po tome sto nakon oble zagrade ne dode vitica);
    moze se pojaviti samostalno ili kao desna strana pridruživanja varijabli
    
    6) operator ~ (alias info) koristi se za dobivanje raznih informacija o biljci određenih
        njenom cvjetnom formulom t.d. se stavi npr. info €cvijet; umjesto cvjetne varijable može doći
        i sekvenca gena ili latinski naziv ili cvjetna formula
            - podaci o biljci se ispisuju i ništa se ne vraća
    
    7) print u datoteku pomocu kljucne rijeci 'datw'; npr. datw("ime.txt", nesto) gdje nesto moze biti
    cvjetna varijabla, numericka varijabla, broj, cvjetna formula, sekvenca gena ili latinski naziv
    
    8) citanje iz datoteke pomocu kljucne rijeci 'datread'; npr $x = datread("ime.txt")
    
    9) konacni tip podataka (flower formula
        nalazit ce se u uglatim zagradama i sastojat ce se od velikih i malih slova i brojeva;
        (https://en.wikipedia.org/wiki/Floral_formula)
        
    7) potencijalno beskonacni tip podatka (sekvence dna - zapocinje s % i smije sadržavati samo
        slova A, C, T, G)
        
    8) operator ? (alias ed) koristi se za racunanje genetske udaljenosti(evolutionary distance);
        to je višemjesni operator sto znaci da se moze pozvati na proizvoljno mnogo biljaka;
        tim biljkama ce se genomi usporedivati do duljine biljke s najkracim genomom i
        ispisat ce se one dvije biljke s najmanjom razlikom, a vratiti ce na koliko se mjesta podudaraju
        geni u genetskom kodu; kao i info moze se pozvati na latinskom nazivu, sekvencama gena, cvjetnoj 
        formuli ili cvjetnoj varijabli
            -unos: nesto ? Rosa rubiginosa ? Rosa rugosa, gdje je nesto latinski naziv, sekvenca gena,
            cvjetna formula neke biljke ili cvjetna varijabla
            -analogan unos: €cvijet cmp Rosa rubiginosa cmp Rosa rugosa
        
    9) operator ß (alias cmp) koristi se za pronalazak genetski najblizeg cvijeta, višemjesni je;
        npr "Rosa Rubiginosa ß Rosa rugosa ß Olea europaea" ce odlučiti je li Rosa Rugosa
        ili Olea europaea genetski bliža cvijetu Rosa Rubiginosa; takoder se moze proslijediti latinski naziv,
        genetska sekvenca, cvjetna formula biljke ili cvjetna varijabla
            -omogucen je i unos: Olea europaea ß, koji ce genetski kod zadane biljke usporediti sa svim
            genetskim kodovima biljaka koji se nalaze u tablici podataka
            -unos: Citrus limon ß Acer palmatum ß, usporedit ce genetske kodove Citrus limona i Acera palmatuma,
            nece pretrazivati bazu (dozvoljen je dangling ß)
            
    10) sql naredba za unos cvijeta u tablicu pomocu operator '->' (alias: unesi)
            -primjer: ->Rosa rubiginosa->[K5C5AG10]->%ATGCTGACGTACGTTA
            -primjer: unesi Rosa rubiginosa unesi [K5C5AG10] unesi %ATGCTGACGTACGTTA
        gornje naredbe unose u tablicu redak gdje je ime Rosa rubiginosa, cvjetna formula je [K5C5AG10])
        
    11) sql naredba za pronalazak podataka o cvijetu iz tablice pomocu operatora '<-' (alias: dohvati)
            -unos: <-Rosa rubiginosa, ispis: Rosa rubiginosa  [K5C5AG10]  %ATGCTGACGTACGTTA
            -analogni unos: dohvati Rosa rubiginosa
        
    napomena: korisnik ne moze definirati funkciju s imenom 'program' jer je to rezervirano za main
'''
# zadatak
* Jezik mora podržavati sljedeće:
  * interaktivni način rada (korisnik utipkava naredbu po naredbu),
  * aritmetičke izraze s višemjesnim operatorima te varijable,
  * petlje koje se vrte onoliko puta kolika je vrijednost varijable,
  * definicije funkcija i funkcijske pozive,
  * barem dva posebna tipa podataka neuobičajenih u (poznatijim) programskim jezicima; jedan tip smije biti konačan (npr. ternarni ishodi za fiksan broj uzoraka nakon ultracentrifugiranja, cvjetne formule za sve dosad poznate cvjetove, itd.), a drugi tip mora biti potencijalno beskonačan (nema unaprijed fiksiran broj elemenata, npr. sekvence DNA proizvoljne duljine),
  * barem tri korisna operatora za rad s gornjim posebnim tipovima podataka
  * barem jedan alternativni način pisanja (alias) za svaki od tih operatora,
  * unos iz datoteke i ispis u datoteku te
  * jednolinijske komentare.
* Napišite lekser, gramatiku i parser te semantički analizator (npr. optimizator) za
svoj jezik. Napišite i interpreter ili kompajler koji vizualizira/ispisuje/prevodi
rezultate obrade. Dokumentirajte svoj kod komentarima i/ili tekstom u odvojenoj datoteci.
* Napišite barem tri programa: dva za svakodnevnu upotrebu vašeg jezika te
jedan krajnje impresivan program koji bi mogao dovesti do novih znanstvenih
otkrića. Kompliciranije dijelove tih programa pojasnite komentarima u njihovom kodu.
* Za dodatne bodove, proširite jezik daljnjim mogućnostima relevantnim za
ciljano znanstveno istraživanje i/ili napravite kostur/skicu1
znanstvenog rada u
LATEX-u koji sadrži rezultate obrade koje ste dobili pokretanjem vaših programa.
