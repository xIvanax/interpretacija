# Ivana
* napravila sam unos iz terminala na foru while petlje jer je sav unos u proslim zadacama tak funkcioniro pa je valjda oke (iako ukljucuje dosta "varanja", ali nemam bolju ideju :( )
* pushala sam datoteku proba.txt u kojoj mozete vidjeti sto sam tocno probavala upisati u terminal
* funkcionira isto kao pythonov shell, znaci ak se unosi funkcija ona se pamti, a ak se unosi bilo sta drugo smatra se dijelom glavnom programa
* unos ; oznacava da korisnik zeli izvršiti naredbu i nakon sto izvrsi neku naredbu moze opet izvrsavati naredbe (dakle korisnik moze u bilo kojem trenu definirati neku funkciju ili napisati naredbu, ima opciju izvršavanja naredbi jednu po jednu t.d. nakon svake upise ;, a moze i unositi proizvoljan broj naredbi)
* trenutne restrikcije koje bi vjv trebalo popraviti su: _ako vidite jos neke restrikcije zapisite ih/ako rijesite neke retsrikcije zapisite koje ste rijesili_
  * poziv funkcije funkcionira samo ako se pridruzi nekoj varijabli i svaka funkcija mora nesto vratiti (osim main-a koji uvijek vrati 0)
* __nisam testirala jos sto se tocno "smije" u smislu hoce li se program zaliti ako cvjetnoj varijabli probam pridruziti broj i slicno - mislim da bi bilo dobro da svi testiramo sve sta nam padne na pamet i da onda ovdje u section "Žalbe" napisemo sto smo testirali i sto valja/ne valja__
# Žalbe
* for petlja moze imati i NUMVAR i BROJ prije {
* trenutno pri citanju iz sql tablice ne pazimo na mogucnost jel fali neki podatak ( ja mislim) - zelimo li pazit na to? _~Ivana_
* ne radi pridruzivanje funkcije tipa $x =f($y) - iz nekog razloga proguta =f kao ime funkcije umjesto da zasebno proguta = i f
* 
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
