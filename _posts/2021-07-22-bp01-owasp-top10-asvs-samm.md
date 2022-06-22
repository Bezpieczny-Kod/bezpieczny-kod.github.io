---
layout: post
author: Andrzej Dyjak
title: Wszystko co musisz wiedzieć o projektach OWASP Top 10, ASVS i SAMM
description: Transkrypcja pierwszego odcinka podcastu Bezpieczna Produkcja, w którym omówiliśmy flagowe projekty OWASP — Top 10, Application Security Verification Standard (ASVS) oraz Software Assurance Maturity Model (SAMM).
permalink: /owasp-top10-asvs-samm/
---

Transkrypcja w formie artykułu pierwszego odcinka podcastu [Bezpieczna Produkcja](https://bezpiecznykod.pl/podcast), w którym przybliżyłem flagowe projekty OWASP — Top 10, Application Security Verification Standard (ASVS) oraz Software Assurance Maturity Model (SAMM).

<!--more-->

Odcinek możesz przesłuchać poniżej lub na wszystkich większych platformach, m.in. [Spotify](https://bezpiecznykod.pl/spotify), [Apple Podcasts](https://bezpiecznykod.pl/apple) czy [Google Podcasts](https://bezpiecznykod.pl/google).

<iframe style="border-radius:12px" src="https://open.spotify.com/embed/episode/6DawYXgpZEvv6h0b5PPIOh?utm_source=generator" width="100%" height="232" frameBorder="0" allowfullscreen="" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture"></iframe>

# Spis treści

- [Wprowadzenie](#wprowadzenie)
- [OWASP Top 10](#owasp-top-10)
- [OWASP Application Security Verification Standard](#owasp-application-security-verification-standard)
- [OWASP Software Assurance Maturity Model](#owasp-software-assurance-maturity-model)
- [Podsumowanie](#podsumowanie)
- [Referencje](#referencje)

# Wprowadzenie

Na samym początku wypadałoby wyjaśnić czym w ogóle jest OWASP.

OWASP, czyli Open Web Application Security Project jest otwartą globalną społecznością działającą formalnie jako organizacja non-profit w Stanach Zjednoczonych. Jej celem jest umożliwienie innym podmiotom na rynku tworzenia, nabywania oraz utrzymywania oprogramowania, któremu można zaufać.

I to tyle, ale wiedząc już czym jest OWASP to na marginesie odniosę się do błędu, który widzę na rynku. Mianowicie często spotykam zapisy mówiące o "metodyce OWASP" no i brzmi to tak samo jakbym powiedział "metodyka Toyota" w odniesieniu do Lean czy Kanbana – specjaliści zrozumieją skrót myślowy, bo znają kontekst natomiast osoby postronne błędnie przyjmą, że OWASP jest metodyką, a tak po prostu nie jest.

Ważne jest też to, że OWASP jako organizacja jest neutralny i nie oferuje certyfikacji. A więc przykładowo jeżeli usługodawca chce wystawiać certyfikację zgodności z OWASP ASVS to robi to "na własną rękę". OWASP takiego podejścia nie potępia, a wręcz przeciwnie – daje wskazówki usługodawcom jak można takie coś stosować w praktyce, ale jasno odcina się od oficjalnej certyfikacji.

Mała uwaga zanim przejdę do omawiania projektów: Pod koniec odcinka zrobię podsumowanie i podpowiem do czego konkretnie można zastosować te projekty we własnej organizacji, więc warto wysłuchać ten odcinek do końca.

# OWASP Top 10

![OWASP Top 10 logo](/public/TOP_10_logo.png 'OWASP Top 10 logo')

OWASP Top 10 to lista dziesięciu najczęściej wystepujących słabości (weaknesses) w web aplikacjach. To, że jest to lista Top-10 wskazuje na jakiś rodzaj sortowania i rzeczywiście OWASP Top 10 jest posortowany przez ryzyko w kontekście typowej organizacji. Innymi słowy OWASP Top 10 nadaje krytyczność danej słabości dzięki czemu jako odbiorca wiemy, że np. "A1: Wstrzyknięcia" dla typowej organizacji powinien być większym problemem niż "A10: Niewystarczające logowanie i monitorowanie".

Krótkie wyjaśnienie terminów, bo autorzy dokumentu sami mają z tym problemy i używają ich wymiennie:

- Czym jest słabość (weakness)? Słabość to typ problemu, który w specjalnych okolicznościach może prowadzić do powstania podatności w produkcie (czyli aplikacji lub systemie IT),
- Ok, a czym w takim wypadku jest podatność (vulnerability)? Podatność to wystąpienie słabości (pojedynczej lub wielu połączonych) w danym produkcie,
- I na koniec trzeba powiedzieć czym jest ryzyko (risk) żeby zobaczyć, że Top 10 nie jest listą ryzyk. Ryzyko —według NIST— to oczekiwanie straty wyrażone jako prawdopodobieństwo wykorzystania konkretnej podatności przez konkretne zagrożenie prowadzące do konkretnego szkodliwego efektu. A więc bez kontekstu nie możemy ocenić ryzyka.

Pierwsza wersja OWASP Top 10 została wydana w roku 2003. Ale chwila, chwila, jaka "pierwsza wersja"? Ano taka, że Top 10 zmienia się w czasie – pewne problemy znikają, a na ich miejsce pojawiają się inne np. Cross-Site Request Forgery (CSRF lub C-SURF) znajdowała się na liście Top 10 2013, ale w Top 10 2017 zniknęła.

Najnowsza wersja OWASP Top 10 jest z roku 2017, a w tym roku —czyli roku 2021 kiedy nagrywam ten podcast— ma zostać wydane długo wyczekiwane uaktualnienie <sup id="fnref:1"><a href="#fn:1">1</a></sup>.

Warto nadmienić, że jednym z celów Top 10 jest bycie zgodnym z rzeczywistością w większości przypadków. I ta "większość przypadków" jest tutaj ważna i wymaga komentarza ponieważ jeżeli będziemy chcieli być bardziej szczegółowi to takich list Top 10 możemy mieć więcej. Czemu? Bo typowe słabości różnią się po pierwsze między stosami technologicznymi (np. w typowej aplikacji PHP znajdziemy inne problemy niż w typowej aplikacji Railsowej) oraz po drugie różnią się również między zespołami (to znaczy, że różne zespoły wytwórcze popełniają różne typowe dla siebie błędy).

Wspominam o tym po części dlatego, żeby dać Ci do myślenia, że OWASP Top 10 nie jest idealny (chociaż dobrze jest mieć Top 10 jako pewnego rodzaju benchmark pasujący do 80% przypadków, czyli reguła Pareto 80:20), ale również dlatego żeby od razu poinformować, że istnieją inne listy OWASP Top 10 – dla przykładu OWASP Top 10 Serverless czy OWASP Top 10 API.

Oryginalnym celem Top 10 był wzrost świadomości wśród deweloperów i menedżerów, ale końcem końców Top 10 stał się niejako standardem rynkowym. Tutaj duża gwiazdka – to nie jest standard *per se* czego twórcy zresztą nie kryją i jasno mówią, że jeżeli potrzebny jest faktyczny standard to powinno się użyć ASVS. A poza wskazaniem ASVS jako standardu, rekomendują również stworzenie Programu Bezpieczeństwa Aplikacji i tutaj wskazują OWASP SAMM. O obu tych projektach opowiem w dalszej części tego odcinka.

Najnowsza wersja OWASP Top 10 powstała na bazie danych dostarczonych przez społeczność i składa się po pierwsze z danych od ponad 40 firm związanych z cyberbezpieczeństwem oraz po drugie z ponad 500 wypełnionych ankiet przez ludzi związanych z branżą. Łącznie dane te dają wgląd w ponad 100,000 podatności z aplikacji z realnego świata (zarówno w monolitach jak i nowoczesnych mikroserwisach).

Ok, dużo już powiedziałem o tym czym jest OWASP Top 10, ale jeszcze nie wymieniłem najważniejszego, czyli jakie słabości się na tej liście obecnie znajdują. Najnowsza wersja OWASP Top 10 z roku 2017 wygląda następująco:

- Wstrzyknięcia (Injection),
- Popsute uwierzytelnianie (Broken Authentication),
- Ujawnienie danych wrażliwych (Sensitive Data Exposure),
- Zewnętrzne encje XML (XML External Entities),
- Popsute zarządzanie dostępem (Broken Access Control),
- Błędna konfiguracja (Security Misconfiguration),
- Cross-Site Scripting,
- Niebezpieczna deserializacja (Insecure Deserialization),
- Używanie komponentów ze znanymi podatnościami (Using components with known vulnerabilities),
- Niewystarczające logowanie i monitorowanie (Insufficient Logging & Monitoring).

Pewnym problemem, który mnie osobiście jako praktyka lekko mierzi jest mieszanie poziomów abstrakcji. Czasami autorzy używają konkretnej słabości (np. Cross-Site Scripting), a kiedy indziej używają klasy słabości (np. Wstrzyknięcia), w której zawiera się wiele różnych słabości (w przypadku Wstrzyknięć może to być SQL Injection, Command Injection, ale również i Cross-Site Scripting, który na koniec dnia również polega na wstrzyknięciu kodu). To nie jest duży problem, ale warto być go świadomym jeżeli pełnisz rolę specjalisty do spraw bezpieczeństwa.

Każdy opis słabości zajmuje jedną stronę A4 i zawiera następujące sekcje:

- Ryzyko obliczane według OWASP Risk Rating Methodology (tutaj autorzy robią to pod kątem typowej organizacji i nie określają wpływu na biznes, a tak na prawdę ten kawałek jest najważniejszy). W osobnej sekcji o ryzyku stwierdzają też, że obliczenie ryzyka oraz związanego z nim apetytu na ryzyko należy do samej organizacji,
- Listę sytuacji, które mogą prowadzić do tego, że aplikacja będzie podatna,
- Przykładowe scenariusze ataku, czyli wykorzystania podatności,
- Sposoby zapobiegania,
- Referencje (najczęściej do innych dokumentów OWASP - ASVS, Proactive Controls, Cheat Sheets, i innych <sup id="fnref:2"><a href="#fn:2">2</a></sup>).

Często przeoczanym dodatkiem do OWASP Top 10 są rozdziały z rekomendacjami podzielonymi na role takie jak: Deweloper, Tester, CISO (Chief Information Security Officer), oraz Menedżer. Postaram się je streścić w kilku punktach.

W poradach dla deweloperów znajdziemy wskazówki odnośnie aspektów takich jak:

- Wymagania bezpieczeństwa względem aplikacji (rekomendacja ASVS jako bazy dla takowych),
- Architektura bezpieczeństwa aplikacji (rekomendacja dokumentów Cheat Sheets Series),
- Kontrole bezpieczeństwa (rekomendacja Proactive Controls),
- Bezpieczeństwo w procesie wytwórczym (S-SDLC), gdzie rekomendują SAMM,
- i na sam koniec rekomendacja edukacji bezpieczeństwa wśród deweloperów.

W poradach dla testerów znajdziemy wskazówki takie jak:

- Zrozum model zagrożeń testowanej aplikacji (priorytety przychodzą z modeli zagrożeń więc jeżeli takowych nie masz jako tester to dobrze jest zacząć od ich stworzenia),
- Zrozum proces wytwórczy (słuszna uwaga o tym, że jeżeli nie rozumiesz SDLC swojej organizacji to nie będziesz działać efektywnie),
- Posiadaj strategię testowania (polecają m.in. ASVS),
- Osiągnij zadowalające pokrycie testami automatycznymi w całym portfolio aplikacji; Przyłóż szczególną wagę do komunikacji tego co znajdujesz (pomiń żargon, idź tam gdzie są deweloperzy np. Pull Request w repozytorium kodu jest lepszy niż raport w PDF),
- Nowoczesny proces wytwórczy wymaga testowania bezpieczeństwa aplikacji w trybie ciągłym poprzez automatyzację i jest to tu uwypuklone,
- Również ważna uwaga – autorzy już w 2017 mocno naciskali na to, że dni w których można było puszczać skany podatności czy wykonywać testy penetracyjne raz na rok są już za nami. Zwinne metodyki wytwarzania oprogramowania oraz DevOps zmieniły reguły gry.

Następnie porady dla organizacji (czyli roli CISO) - tutaj porady są związane z implementacją programu bezpieczeństwa w procesie wytwórczym i w zasadzie nie wykraczają poza to co można znaleźć w OWASP SAMM, o którym będę dzisiaj jeszcze mówił.

I na sam koniec porady dla menedżerów zawierające cenne wskazówki dla menedżerów aplikacji w sprawie włączenia bezpieczeństwa w procesy takie jak:

- Zarządzanie wymaganiami i zasobami,
- Tworzenie <abbr title="Request For Proposal">RFP</abbr> i kontraktowanie projektów,
- Planowanie i projektowanie oprogramowania,
- Wypuszczanie i testowanie wersji,
- Operacje i zarządzanie zmianą,
- No i na sam koniec w proces wygaszania systemów.

Ok, w zasadzie opowiedziałem o najważniejszych aspektach OWASP Top 10. A czy mamy jakieś alternatywy? Tak! Jak najbardziej istnieją podobne listy.

Dobrym przykładem jest HackerOne Top 10, czyli Top 10 tworzone przez największą na świecie platformę Bug Bounty, przez którą rocznie przelatuje prawie 200,000 raportów faktycznych podatności. I teraz ciekawy fakt: Pokrycie pomiędzy najnowszym HackerOne Top 10, a OWASP Top 10 2017 jest duże, ale różnice występują (np. lista HackerOne zawiera zarówno CSRF oraz SSRF, a nie zawiera XXE).

Warto również zwrócić uwagę na liczby: OWASP Top 10 budowany jest na podstawie ok. 100,000 podatności, a HackerOne Top 10 prawie 200,000. Co więcej źródła danych również mają tutaj znaczenie – udział w programach Bug Bounty jest typowy dla pewnego rodzaju firm (według statystyk HackerOne najczęściej są to firmy technologiczne), a to znowu ma wpływ na to jakie technologie są używane pod spodem (i stąd może wynikać na przykład brak XML External Entities typowego dla Javy używanej w dużych korporacjach, a nietypowego dla np. Pythona używanego w firmach jednorożcach z doliny krzemowej).

Inną dobrze znaną na rynku listą typowych słabości jest CWE Top 25. Jej dużym plusem jest przywiązywanie uwagi do poziomu abstrakcji – każda słabość wylistowana w CWE Top 25 jest osobnym bytem (nie jak w przypadku OWASP Top 10, gdzie czasem to osobny byt, a czasem klasa). Z kolei minusem jest wrzucenie do worka wszystkich słabości niezależnie od typu aplikacji, więc przykładowo w najnowszym CWE Top 25 (który również zmienia się w czasie) znajdziemy np. Use-After-Free, i ta słabość jest typowa dla aplikacji pisanych w językach niskopoziomowych takich jak przeglądarki.

I to by było na tyle o OWASP Top 10. Najważniejsze informacje zostały przekazane i możemy iść dalej do OWASP ASVS!

# OWASP Application Security Verification Standard

Application Security Verification Standard (w skrócie ASVS) to zestaw wymagań i kontroli bezpieczeństwa —zarówno funkcjonalnych jak i niefunkcjonalnych— które mogą zostać użyte podczas fazy projektowania, implementacji i weryfikacji web aplikacji w celu zapewnienia odpowiedniego poziomu bezpieczeństwa.

Pierwsza wersja ASVS została wydana w roku 2009. ASVS od tego czasu jest aktywnie rozwijany, a jego najnowsza wersja —czyli wersja 4— została wydana w roku 2019 i jest wyrównana z tym w jaki sposób działają obecne aplikacje (np. architektura oparta o mikroserwisy versus monolit).

Najnowsza wersja ASVS jest zgodna ze standardem NIST 800-63-3, który jest obszernym standardem uwierzytelniania. Co więcej wymagania i kontrolki zawarte w ASVS są w dużej mierze zmapowane do CWE, czyli listy która enumeruje typowe słabości występujące w oprogramowaniu i o której pobieżnie wspomniałem omawiając Top 10.

Aktualna wersja standardu podzielona jest na 14 obszarów i są nimi kolejno:

- Architektura, projektowanie i modelowanie zagrożeń (Architecture, Design and Threat Modeling),
- Uwierzytelnianie (Authentication),
- Zarządzanie sesją (Session Management),
- Kontrola dostępu (Access Control),
- Walidacja, Oczyszczanie i Enkodowanie (Validation, Sanitization and Encoding),
- Kryptografia (Stored Cryptography),
- Obsługa Błędów i Logowanie (Error Handling and Logging),
- Ochrona Danych (Data Protection),
- Komunikacja (Communications),
- Złośliwy Kod (Malicious Code),
- Logika Biznesowa (Business Logic),
- Pliki i Zasoby (File and Resources),
- API i Web Serwisy (API and Web Service),
- Konfiguracja (Configuration).

W obrębie każdego z tych obszarów znajdziemy sekcję określającą cel oraz referencje. Poza tym każdy obszar zawiera kontrolki i wymagania bezpieczeństwa, które zgrupowane są w mniejsze podobszary, dzięki czemu łatwo jest go używać w różnych przypadkach. Przykładowo obszar API i Web Serwisy podzielony jest na podobszary:

- Ogólne Bezpieczeństwo Web Serwisów (Generic Web Service Security),
- Web Serwisy Oparte o REST (RESTful Web Service),
- Web Serwisy Oparte o SOAP (SOAP Web Service),
- oraz GraphQL i inne warstwy danych w web serwisach (GraphQL and other Web Service Data Layer).

I teraz, jeżeli w danej aplikacji korzystamy z REST, a nie korzystamy z SOAP to możemy SOAP pominąć i dalej otrzymujemy po pierwsze pewne generyczne wymagania dla API, po drugie specyficzne wymagania dla API opartych o REST oraz po trzecie wymagania dla GraphQL i innych warstw danych.

Na początku mówiąc o tym czym jest ASVS wspomniałem o "zapewnianiu odpowiedniego poziomu bezpieczeństwa" i ma to tutaj znaczenie. Każde wymaganie ASVS należy do jednego z 3 poziomów weryfikacji, gdzie każdy kolejny poziom ma za zadanie podnosić bezpieczeństwo w coraz większym stopniu. Przykładowo:

- Kontrolka 13.2.2, w wolnym tłumaczeniu mówiąca, że "gdy korzystam z JSON to przed zaakceptowanie danych wejściowych musi nastąpić walidacja JSON-a" wymagana jest dla aplikacji na poziomie od 1 w górę
- Ale już kontrolka 13.2.4, która w wolnym tłumaczeniu mówi o tym, że "serwisy REST-owe muszą mieć mechanizm obronny przed atakami zautomatyzowanymi w szczególności jeżeli API jest bez uwierzytelniania" to spełnienie tej kontrolki wymagane jest dopiero od poziomu 2 w górę.

Wchodząc bardziej szczegółowo w poszczególne poziomy możemy określić pewne ich właściwości.

![ASVS poziom 1 (L1)](/public/ASVS-level-1.png 'ASVS poziom 1 (L1)')

Wymagania ASVS na poziomie 1 rekomendowane są dla projektów z niskim zapotrzebowaniem na bezpieczeństwo. Ten poziom to takie niezbędne minimum. Co więcej poziom 1 można w dużej mierze —ale nie 100%— testować automatycznie.

Wymagania na poziomie 1 pokrywają całość OWASP Top 10 z roku 2017 (za wyjątkiem A10, czyli logowania) oraz OWASP Proactive Controls 2018. Oznacza to tyle, że jeżeli zaadaptujemy ASVS już na poziomie 1 jako standard w procesie bezpiecznego wytwarzania (np. jako podstawę testów bezpieczeństwa) to będziemy mieć z głowy praktycznie cały Top 10.

Dodatkowo ASVS na poziomie 1 jest nadzbiorem sekcji 6.5 standardu PCI DSS w wersji 3.2.1 (sekcja ta zawiera szereg wymagań odnośnie zapobiegania podatnościom w aplikacjach podczas procesu wytwórczego).

Ważną uwagą jest to, że jedynie poziom 1 jest możliwy do przetestowania podejściem black-box (to jest bez dostępu do dokumentacji, kodu źródłowego czy deweloperów i architektów) <sup id="fnref:3"><a href="#fn:3">3</a></sup>.

Autorzy otwarcie krytykują podejście black-box z czym się w 100% zgadzam. W realnym świecie występuje asymetria – atakujący ma tyle czasu ile potrzebuje, a tester bezpieczeństwa zawsze jest ograniczony czasem przewidzianym na ocenę. Z tego powodu podczas fazy testowania powinno się dołożyć wszelkich starań do tego żeby tester otrzymał tyle informacji ile może. Natomiast testowanie bezpieczeństwa podejściem black-box, które często wykonywane jest w pośpiechu na samym końcu procesu wytwórczego (albo w ogóle) – takie testowanie po prostu nie daje rady pokonać asymetrii pomiędzy cyberprzestępcami, a bezpiecznikami.

Zresztą wyobraźmy sobie sytuację, gdzie zewnętrzny audytor finansowy wchodzi do organizacji i ma ją ocenić pod kątem machlojek ale jednocześnie nie ma dostępu do dokumentów podatkowych czy ludzi odpowiedzialnych za kontroling. No brzmi śmiesznie, ale dokładnie taka sytuacja jest na porządku dziennym podczas testowania bezpieczeństwa aplikacji.

I właśnie dlatego autorzy mocno zachęcają do testowania bezpieczeństwa podejściem hybrydowym łącząc testy bezpieczeństwa z audytem kodu, dostępem do deweloperów i architektów, oraz dokumentacji.

<div class="message">
Uwaga: Tutaj nie chodzi o podejście white-box – podejście hybrydowe to co innego, wyjaśnię różnicę w przyszłych odcinkach podcastu <sup id="fnref:3"><a href="#fn:3">3</a></sup>.
</div>

![ASVS poziom 2 (L2)](/public/ASVS-level-2.png 'ASVS poziom 2 (L2)')

Wymagania ASVS na poziomie 2 kierowane są do aplikacji wykonujących ważne operacje biznesowe (np. przetwarzanie danych osobowych w kontekście RODO). Ten poziom jest rekomendowany dla większości aplikacji.

Spełnienie ASVS na poziomie 2 zapewnia, że w aplikacji są obecne kontrole bezpieczeństwa skutecznie broniące przed większością podatności.

![ASVS poziom 3 (L3)](/public/ASVS-level-3.png 'ASVS poziom 3 (3)')

Natomiast ASVS na poziomie 3 —czyli najwyższym— rekomenduje się dla aplikacji krytycznych, na przykład:

- Aplikacji, które wykonują operacje finansowe,
- Aplikacji, które przetwarzają dane medyczne.

Mówiąc ogólnie ten poziom jest dla aplikacji i systemów IT, które wymagają najwyższego poziomu zaufania. W związku z tym aplikacja spełniająca wymagania poziomu 3 musi stać na najwyższym poziomie nie tylko w kwestii implementacji (a więc wykazać się brakiem skomplikowanych podatności), ale również ogólnego projektu architektury (to znaczy powinny być stosowanie zasady bezpiecznej architektury takie jak Defense in Depth, Principle of Least Privilege, i tym podobne).

Skuteczne testowanie aplikacji pod kątem poziomu 3 wymaga ścisłej współpracy z zespołami wytwórczymi.

Wybór poziomu ASVS zależy od kontekstu danej organizacji (tj. profilu ryzyka, profilu zagrożeń, itp.) oraz konkretnej aplikacji i danych jakie przetwarza.

Trzeba również uwypuklić fakt, że ponad połowy kontroli zawartych w ASVS nie da się przetestować automatami więc wymagają podejścia manualnego.

OWASP ASVS można używać w wielu kontekstach:

- Dla architektów ASVS może być świetną podstawą do stworzenia bezpiecznej architektury rozwiązania,
- Dla deweloperów ASVS to podstawa do Secure Coding Checklist, która może być weryfikowana podczas Code Review,
- Dla deweloperów i testerów ASVS może być podstawą do automatycznych testów jednostkowych oraz integracyjnych,
- Z kolei menedżerzy mogą wykorzystać ASVS przy zamawianiu oprogramowania od firm trzecich (w najprostszym wydaniu – w umowie można zawrzeć informacje, że odbiór aplikacji podyktowany jest wynikiem pozytywnym audytu pod kątem ASVS na określonym poziomie),
- CISO na poziomie organizacji może skorzystać z ASVS jako drivera dla Zwinnego Bezpieczeństwa Aplikacji (Agile AppSec),
- I ostatecznie ASVS może być potraktowany jako podstawa szkolenia dla ludzi uczestniczących w procesie wytwórczym (deweloperzy, architekci, testerzy) i tutaj uwaga autorów, która pokrywa się z moim doświadczeniem – większość szkoleń dostępnych na rynku to szkolenia z etycznego hackingu, bez wchodzenia w szczegóły czemu jakiś problem wystąpił i jak go rozwiązać. To samo zauważyłem ja na naszym lokalnym rynku skądinąd dlatego w [swoich szkoleniach](https://bezpiecznykod.pl/szkolenia){:target="_blank"} zmieniam ten stan rzeczy.

ASVS nie ma odpowiedników branżowych, ale istnieją standardy pokrewne:

- OWASP Mobile Application Security Verification Standard (MASVS) jako odpowiednik dla aplikacji mobilnych,
- OWASP Internet of Things Verification Standard (ISVS) jako odpowiednik dla aplikacji IoT oraz embedded,
- OWASP Software Component Verification Standard (SCVS) jako standard skupiający się na zapewnieniu odpowiedniego poziomu bezpieczeństwa łańcucha dostawczego,
- Dla aplikacji natywnych (desktop/server, czasami zwane thick-client) nie ma odpowiednika, ale ASVS w dużej mierze można również użyć do aplikacji natywnych.

No i dobrnęliśmy do końca tej sekcji. Teraz kiedy już wiesz czym jest Top 10 oraz ASVS, pora dowiedzieć się czym jest OWASP SAMM.

# OWASP Software Assurance Maturity Model

Software Assurance Maturity Model (w skrócie SAMM) jest frameworkiem pozwalającym organizacjom na ocenę lub stworzenie i implementację własnej strategii bezpieczeństwa aplikacji.

Opisując SAMM-a skupię się głównie na wersji 1.5 pomimo tego, że najnowszą wersją jest wersja 2. Robię to z trzech powodów: po pierwsze z wersją 1.5 mam więcej doświadczenia, po drugie różnice pomiędzy wersją 1.5 a wersją najnowszą nie wpływają na zrozumienie fundamentów, a po trzecie łatwiej ją skontrastować z innym narzędziem o którym wspomnę dzisiaj i opowiem szerzej w kolejnych odcinkach.

Wracając do opisu – ważne, że SAMM to model dojrzałości, a nie lista wymagań. Dzięki temu pozwala ocenić stopień w jakim realizujemy daną aktywność, a nie tylko zero-jedynkowo stwierdzić czy dana aktywność jest spełniona czy nie.

SAMM jako framework pasuje zarówno do małych, średnich jak i dużych organizacji. Dodatkowo można go aplikować wyrywkowo w obrębie organizacji, konkretnej linii biznesowej, a wyrywkami nawet w ramach konkretnego projektu.

Budując SAMM-a autorzy oparli się o kilka fundamentalnych zasad:

- Po pierwsze: Nie ma jednego złotego środka na rozwiązanie problemów we wszystkich organizacjach,
- Po drugie: Zmiana zachowania organizacji to powolna sprawa,
- Po trzecie: Wszystkie rekomendowane kroki powinny być proste, jasno zdefiniowane i mierzalne,
- I po czwarte: Wytyczne związane z bezpieczeństwem muszą być nakazowe (prescriptive), to znaczy, że eksperci mówią nam jak powinno być. I to jest ważna uwaga. SAMM zbudowany jest podejściem opartym o wizję tego jak –według ekspertów– powinien wyglądać bezpieczny proces wytwórczy.

Wersja 1.5 SAMM-a, składa się z 4 funkcji biznesowych: Nadzoru, Konstruowania, Weryfikacji i Operacji. Każda z nich zawiera w sobie aktywności zachodzące podczas procesu wytwórczego. Mówiąc inaczej – każda firma tworząca oprogramowanie posiada wszystkie te funkcje oraz realizuje poszczególne aktywności w jakimś stopniu.

- Dla każdej funkcji biznesowej SAMM definiuje 3 praktyki bezpieczeństwa z nią związaną,
- Każda praktyka jest obszarem aktywności powiązanych z bezpieczeństwem danej funkcji biznesowej,
- Sumując SAMM zawiera 12 praktyk bezpieczeństwa, które można traktować jako osobne silosy należące do jednej z 4 funkcji biznesowych,
- Każda praktyka bezpieczeństwa posiada 3 poziomy dojrzałości, a każdy poziom definiuje cele wymagane do jego osiągnięcia. Co więcej, każda praktyka może być ulepszana osobno, ale łączenie powiązanych ze sobą praktyk umożliwia optymalizację.

![Wysokopoziomowe spojrzenie na SAMM 1.5](/public/samm-overview.png 'SAMM 1.5 overview')

Nie mając przed oczami dokumentu <sup id="fnref:4"><a href="#fn:4">4</a></sup> można się trochę pogubić w tym co powiedziałem. W praktyce natomiast wygląda to następująco:

- Funkcja biznesowa Nadzór (Governance) odnosi się do procesów i aktywności związanych z tym jak organizacja zarządza procesem wytwórczym i innymi procesami związanymi pośrednio z wytwórstwem. W obrębie tej funkcji mam następujące praktyki:
    - Praktyka bezpieczeństwa Strategia i Mierniki (Strategy & Metrics) – zawiera ogólną strategię programu bezpieczeństwa aplikacji oraz sposoby mierzenia progresu lub regresu w czasie,
    - Praktyka bezpieczeństwa Polityki i Zgodność (Policy & Compliance) – zawiera aktywności potrzebne do stworzenia frameworka kontroli w celu zapewniania bezpieczeństwa w procesie wytwórczym i utrzymaniu,
    - Praktyka bezpieczeństwa Edukacja (Education & Guidance) – zawiera aktywności związane ze zwiększaniem wiedzy na temat bezpieczeństwa w całym przekroju organizacji. Od zwiększania świadomości dla osób biznesowych do zwiększania umiejętności twardych dla osób uczestniczących w procesie SDLC.
<div class="message">
Tutaj warto uwypuklić, że taka edukacja musi zostać podzielona na poziomy, bo czym innym jest szkolenie z bezpieczeństwa aplikacji dla menedżerów i liderów, czym innym szkolenie z etycznego hackingu dla testerów QA, a jeszcze czym innym szkolenie z bezpieczeństwa dla deweloperów i architektów (<i>notabene</i> dlatego <a href="https://bezpiecznykod.pl/szkolenia" target="_blank">w Bezpieczny Kod mamy różne rodzaje szkoleń</a>).
</div>
- Funkcja biznesowa Konstruowanie (Construction) odnosi się do procesów i aktywności bezpieczeństwa, które powinny się odbyć na etapie projektowania. W obrębie tej funkcji mam następujące praktyki:
    - Praktyka bezpieczeństwa Ocena Zagrożeń (Threat Assessment) znana szerzej również jako modelowanie zagrożeń – zawiera aktywności pomagające zidentyfikować oraz scharakteryzować potencjalne ataki na oprogramowanie firmy po to, aby zrozumieć ryzyko i lepiej nim zarządzać,
    - Praktyka bezpieczeństwa Wymagania Bezpieczeństwa (Security Requirements) – zawiera aktywności związane z definiowaniem i promocją bezpieczeństwa już w fazie określania wymagań rozwiązania,
    - Praktyka bezpieczeństwa Bezpieczna Architektura (Secure Architecture) – zawiera aktywności związane z definicją ogólnej architektury bezpieczeństwa aplikacji w organizacji.
- Funkcja biznesowa Weryfikacja (Verification) skupia się na tym w jaki sposób organizacja podchodzi do weryfikowania bezpieczeństwa artefaktów powstałych w procesie wytwórczym (dla przykładu: kodu aplikacji, obrazów dockera, plików deklaracyjnych środowiska chmurowego, i tym podobnych). W obrębie tej funkcji mam następujące praktyki:
    - Praktyka bezpieczeństwa Przegląd Projektu Rozwiązania (Design Review) – praktyka skupiona na weryfikacji artefaktów powstałych we wcześniejszej fazie projektowania pod kątem bezpieczeństwa (np. Czy są obecne odpowiednie kontrole? Czy projekt rozwiązania jest zgodny z wytycznymi organizacji?),
    - Praktyka bezpieczeństwa Przegląd Implementacji (Implementation Review) – skupia się na przeglądzie kodu, zarówno manualnym (Secure Code Review) jak i automatycznym (analiza statyczna SAST, analiza składu SCA, sekrety, i tym podobne),
    - Praktyka bezpieczeństwa Testowanie Bezpieczeństwa (Security Testing) – czyli typowe testowanie bezpieczeństwa, zarówno automatycznie (DAST) jak i manualnie (ocena podatności, pentesty).
<div class="message">
Tutaj muszę jasno uwypuklić, że Testy Penetracyjne nie grają pierwszych skrzypiec. To ocena podatności wnosi dużo więcej wartości pod kątem bezpieczeństwa do procesu wytwórczego niż pentesty, które z racji tego co i jak testują muszą odbywać się praktycznie na samym końcu znacznie wydłużając pętlę zwrotną <sup id="fnref:5"><a href="#fn:5">5</a></sup>.
</div>
- Funkcja biznesowa Operacje (Operations) skupia się wokół tego jak organizacja zarządza wydaniami oraz ogólnie zmianą w systemach IT. W obrębie tej funkcji mam następujące praktyki:
    - Praktyka bezpieczeństwa Zarządzanie Problemami (Issue Management) – skupia się na ustaleniu procesu zarządzania problemami zarówno wewnętrznymi jak i zewnętrznymi. Aktywności wchodzące w skład tej praktyki są również ważne w Strategii i Metrykach ponieważ im lepsze dane zbieramy, tym lepiej dostroimy naszą strategię,
    - Praktyka bezpieczeństwa Utwardzanie Środowiska (Environment Hardening) – obraca się wokół implementacji kontroli bezpieczeństwa dla środowiska aplikacyjnego, od systemu operacyjnego, przez kontenery i sieć wewnętrzną aż po sieć publiczną,
    - Praktyka bezpieczeństwa Aktywizacja Operacji (Operational Enablement) – aktywności w tej praktyce mają na celu dostarczyć Opsom wszystkiego co potrzeba, aby ich praca odbywała z jak najmniejszym tarciem (tj. friction).

Wcześniej powiedziałem, że SAMM posiada 3 poziomy dojrzałości, ale będąc skrupulatnym można wyszczególnić 4 poziomy dojrzałości, jeżeli zaczniemy od poziomu zero, który wskazuje na totalny brak aktywności w danym zakresie. Kolejne poziomy to:

- Poziom 1, który oznacza podstawowe zrozumienie i możliwość wykonania aktywności w trybie ad-hoc.
- Poziom 2 oznaczający ogólną sprawność i efektywność w wykonywaniu danej aktywności.
- I wreszcie poziom 3, który oznacza mistrzostwo w danej aktywności połączone z działaniem w skali. Działanie w skali jest tutaj ważne – nawet jeżeli dana aktywność jest na najwyższym poziomie w jakimś małym wycinku organizacji to o ile nie jest globalna to nie powinnismy oceniać jej na poziom 3.

A jak te poziomy wyglądają w praktyce? Zobrazuję to na dwóch przykładach praktyk: Edukacji oraz Testowania Bezpieczeństwa.

W przypadku praktyki Edukacja poziomy i wymagania wyglądają następująco:

- Na poziomie 1 wymaga zapewnienia deweloperom dostępu do informacji na temat bezpiecznego programowania. Aktywności jakie należy w tym celu wykonać to: Po pierwsze przeprowadzenie szkolenia technicznego podnoszącego świadomość oraz po drugie zbudowanie i utrzymanie technicznych poradników dla deweloperów (np. na Assurance Program).
- Edukacja na poziomie 2 wymaga szkolenia wszystkich ludzi biorących udział w procesie wytwórczym pod kątem bezpieczeństwa aplikacji, co więcej taka edukacja powinna odpowiadać roli (a więc inne szkolenia dla PM-ów, inne dla testerów i inne dla deweloperów). Aktywności jakie należy wykonać w tym celu to: Po pierwsze przeprowadzenie szkoleń z bezpieczeństwa aplikacji z podziałem na rolę oraz po drugie stworzenie specjalnej roli wewnątrz zespołów, która jest satelitą dla jednostki odpowiadającej za bezpieczeństwo aplikacji (tutaj występują różne nazwy, SAMM określa tę rolę jako "Security Coaches", obecnie częściej można spotkać nazwę "Security Champions").
- Edukacja na poziomie 3 wymaga dogłębnego szkolenia z bezpieczeństwa aplikacji zwieńczonego certyfikacjami. Aktywności jakie należy wykonać w tym celu to: Po pierwsze stworzenie formalnego portalu edukacyjnego z bezpieczeństwa aplikacji wewnątrz firmy oraz po drugie ustanowienie certyfikacji z podziałem na rolę (w to wchodzą oczywiście egzaminy wymagane do uzyskania danego certyfikatu). BTW. Mowa tutaj o certyfikacji wewnętrznej, nie trzeba ALE MOŻNA korzystać z zewnątrz.

Natomiast w przypadku praktyki Testowanie Bezpieczeństwa:

- Na poziomie 1 wymaga ona ustanowienie procesu wykonywania podstawowych testów bezpieczeństwa opartych o wymagania (tutaj może przydać się wcześniej omawiany ASVS). Aktywności jakie należy w tym celu wykonać to: Po pierwsze stworzenie przypadków testowych z wcześniej stworzonych wymagań bezpieczeństwa (np. jeżeli aplikacja ma mieć flagę Secure na ciasteczku sesyjnym to powinien powstać test weryfikujący to wymaganie) oraz po drugie wykonywanie testów penetracyjnych dla kolejnych wydań aplikacji.
- Testowanie na poziomie 2 wymaga wszystkiego tego co na poziomie pierwszym, ale na dokładkę powinniśmy zapewnić, że testowanie bezpieczeństwa podczas wytwarzania dzieje się automatycznie. Aktywności jakie należy w tym celu wykonać to: Po pierwsze używanie narzędzi klasy DAST oraz po drugie wbudowanie testowania bezpieczeństwa w proces wytwórczy (czyli testowanie wydań produkcyjnych się tutaj nie liczy).
- Testowanie na poziomie 3 wymaga skrojenia testów bezpieczeństwa pod każdą aplikację jaką tworzymy, po to aby zapewniać ustanowiony baseline (to o czym mówiliśmy wcześniej – aplikacje pisane w różnych stosach technologicznych mają różne "typowe dla siebie" podatności). Aktywności jakie należy w tym celu wykonać to: Po pierwsze automatyzacja testów bezpieczeństwa ułożona pod każdą aplikację oraz po drugie ustanowić bramki bezpieczeństwa (release gates), które jeżeli nie zostaną osiągnięte to zakończą budowanie paczki niepowodzeniem.

Na początku wspomniałem, że najnowsza wersja SAMM to wersja 2, a omawiając skupiłem się na wersji 1.5. A więc jakie są różnice pomiędzy nimi? Główną zmianą względem starej wersji jest dodanie całkowicie nowej funkcji biznesowej Implementacja (Implementation), która zawiera praktyki związane z zapewnianiem bezpieczeństwa sposobu w jaki wytwarzamy software (np. bezpieczeństwo potoku CICD – i tutaj ważne, że nie mówimy o bezpieczeństwie W POTOKU tylko bezpieczeństwie potoku (np. aktualna i zabezpieczona instancja Jenkinsa)). Dodatkowo funkcje biznesowe Weryfikacja oraz Operacje lekko się zmieniły oraz dodane zostały strumienie – każda praktyka bezpieczeństwa podzielona jest na 2 strumienie.

Niestety wersja 2 dalej —po prawie półtora roku— jest bardziej minimalistyczna niż wersja 1.5. Dokumentacja wersji 1.5 jest po prostu przyjemniejsza w odbiorze. Dodatkowo dla wersji 1.5 istnieją dodatkowe dokumenty pomocnicze, które do tej pory nie zostały przełożone do wersji 2.

Na zakończenie zobaczmy jak sprawa ma się z alternatywami dla SAMM-a. Najbliższym zamiennikiem jest Building Security In Maturity Model znany również jako BSIMM, o którym opowiem szerzej w kolejnych odcinkach, ale już teraz wskażę jedną fundamentalną różnicę względem SAMM-a. Tak jak mówiłem wcześniej, SAMM jest modelem nakazowym (prescriptive) opisującym jak bezpieczny proces powinien wyglądać z perspektywy eksperta. Natomiast BSIMM jest modelem zbudowanym na obserwacji tego jak sprawy faktycznie wyglądają w firmach, które wytwarzają oprogramowanie (to znaczy, że wzięta jest próbka praktyk i aktywności z wielu różnych firm, następnie wyciągnięte są elementy wspólne i na koniec następuje ich ważenie).

# Podsumowanie

Teraz kiedy już wiesz czym jest Top 10, ASVS i SAMM masz już pewnie własne pomysły, gdzie można te narzędzia wykorzystać. Jeżeli nie to moje propozycje są następujące:

- Top 10 najlepiej sprawdzi się w budowie podstawowej świadomości na temat problemów bezpieczeństwa web aplikacji. Poza tym Top 10 można wykorzystać we wczesnych fazach wytwórczych np. jako bibliotekę ataków w sesjach modelowania zagrożeń czy jako mentalną checklistę podczas fazy implementacji (w tym Code Review),
- Z kolei ASVS to świetne narzędzie do oceny podatności aplikacji. Ważne żeby przed skorzystaniem z ASVS jasno sobie zdefiniować poziom, na którym chcemy działać. Poza tym ASVS nada się również jako baza, na której można zbudować checklistę do procesu Secure Code Review. Dużą zaletą wykorzystania ASVS jako bazy do działań w kontekście bezpieczeństwa aplikacji to możliwość badania różnic w czasie, w przeciwieństwie do Top 10, który mocno utrudnia taki pomiar ponieważ jest na zbyt ogólnym poziomie szczegółowości,
<div class="message">
A już zupełnie na marginesie ASVS pomaga również usługodawcom z rynku cyberbezpieczeństwa —takim jak moja firma Bezpieczny Kod— ułatwiając nam oferowanie usług wyrównanych z tym czego potrzebują klienci.
</div>
- Natomiast SAMM pomoże nam po pierwsze w ocenie stanu obecnego procesu wytwórczego pod kątem bezpieczeństwa, po drugie w zbudowaniu skrojonego na miarę programu bezpieczeństwa aplikacji i podzielenie go na fazy implementacji, po trzecie w definicji aktywności związanych z bezpieczeństwem aplikacji dla całej organizacji (tutaj wychodzi nawet lekko poza te ramy poprzez obszar Nadzoru) i po czwarte w pomiarze postępu pomiędzy kolejnymi fazami implementacji. Mówiąc krótko: SAMM pozwala na wprowadzenie zmian systemowych usprawniających bezpieczeństwo dla wszystkich naszych aplikacji.

Warto również zauważyć, że omawiając te 3 flagowe projekty przechodziliśmy od szczegółu do ogółu. Mam tutaj na myśli to, że Top 10 jest najbliżej implementacji, ASVS wychodzi poza samą implementację zahaczając o fazy projektowania i testowania. Natomiast SAMM ma coś do powiedzenia w każdej aktywności związanej z procesem wytwórczym.

<div class="footnotes">
  <ol>
    <li class="footnote" id="fn:1">
      <p>Najnowsze wydanie OWASP Top 10 w wersji 2021 jest już dostępne. <a href="#fnref:1" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:2">
      <p>O projektach OWASP Proactive Controls i Cheat Sheet Series możesz posłuchać w <a href="https://bezpiecznykod.pl/bp02" target="_blank">odcinku drugim</a>. <a href="#fnref:2" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:3">
      <p>O podejściach black-box, white-box, gray-box czy hybrydzie możesz posłuchać w <a href="https://bezpiecznykod.pl/bp05" target="_blank">odcinku piątym</a>. <a href="#fnref:3" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:4">
      <p>Forma artykułu na blogu pozwala na dodanie obrazka, a więc został on dołączony powyżej. <a href="#fnref:4" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:5">
      <p>O ocenie podatności możesz posłuchać w <a href="https://bezpiecznykod.pl/bp07" target="_blank">odcinku siódmym</a>, a o testach penetracyjnych w <a href="https://bezpiecznykod.pl/bp08" target="_blank">odcinku ósmym</a>. <a href="#fnref:5" title="powrót do artykułu"> ↩</a></p>
    </li>
  </ol>
</div>

# Referencje

Omawiane projekty OWASP:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/){:target="_blank"}
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/){:target="_blank"}
- [OWASP Software Assurance Maturity Model](https://owaspsamm.org/){:target="_blank"}

Inne wspomniane projekty OWASP-owe i nie tylko:

- [OWASP Top 10 Serverless](https://owasp.org/www-project-serverless-top-10/){:target="_blank"}
- [OWASP Top 10 API](https://owasp.org/www-project-api-security/){:target="_blank"}
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology){:target="_blank"}
- [OWASP Mobile Application Security Verification Standard](https://github.com/OWASP/owasp-masvs){:target="_blank"}
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/){:target="_blank"}
- [OWASP IoT Security Verification Standard](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS){:target="_blank"}
- [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/){:target="_blank"}
- [HackerOne Top 10](https://www.hackerone.com/top-ten-vulnerabilities){:target="_blank"}
- [CWE Top 25](https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html){:target="_blank"}
- [NIST SP 800-63-3](https://pages.nist.gov/800-63-3/){:target="_blank"}
- [PCI DSS](https://www.pcisecuritystandards.org/){:target="_blank"}
- [Building Security In Maturity Model](https://www.bsimm.com/){:target="_blank"}

Definicje i koncepty:

- [Definicja słabości (weakness) - MITRE](https://cwe.mitre.org/documents/glossary/index.html#Weakness){:target="_blank"}
- [Definicja podatności (vulnerability) – MITRE](https://cwe.mitre.org/documents/glossary/index.html#Vulnerability){:target="_blank"}
- [Definicja słabości (weakness) – NIST](https://csrc.nist.gov/glossary/term/weakness){:target="_blank"}
- [Definicja podatności (vulnerability) – NIST](https://csrc.nist.gov/glossary/term/vulnerability){:target="_blank"}
- [Definicja ryzyka (risk) – NIST](https://csrc.nist.gov/glossary/term/risk){:target="_blank"}
- [Defense in Depth - Wikipedia](https://en.wikipedia.org/wiki/Defense_in_depth_(computing)){:target="_blank"}
- [Principle of Least Privilege - Wikipedia](https://en.wikipedia.org/wiki/Principle_of_least_privilege){:target="_blank"}
