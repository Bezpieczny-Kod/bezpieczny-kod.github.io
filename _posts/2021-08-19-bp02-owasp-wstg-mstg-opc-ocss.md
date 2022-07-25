---
layout: post
author: Andrzej Dyjak
title: Inne projekty OWASP warte poznania, czyli krótko o WSTG, MSTG, OPC i OCSS
description: Transkrypcja w formie artykułu drugiego odcinka podcastu Bezpieczna Produkcja, w którym przybliżyłem te mniej znane, ale równie przydatne projekty OWASP — Web Security Testing Guide (WSTG), Mobile Security Testing Guide (MSTG), Proactive Controls (OPC) oraz Cheat Sheet Series (OCSS).
permalink: /owasp-wstg-mstg-opc-ocss/
---

Transkrypcja w formie artykułu drugiego odcinka podcastu [Bezpieczna Produkcja](https://bezpiecznykod.pl/podcast), w którym przybliżyłem te mniej znane, ale równie przydatne projekty OWASP — Web Security Testing Guide (WSTG), Mobile Security Testing Guide (MSTG), Proactive Controls (OPC) oraz Cheat Sheet Series (OCSS).

<!--more-->

Odcinek możesz przesłuchać poniżej lub na wszystkich większych platformach, m.in. [Spotify](https://bezpiecznykod.pl/spotify), [Apple Podcasts](https://bezpiecznykod.pl/apple) czy [Google Podcasts](https://bezpiecznykod.pl/google).

<div id="buzzsprout-player-9042563"></div><script src="https://www.buzzsprout.com/1667851/9042563-inne-projekty-owasp-warte-poznania-czyli-krotko-o-wstg-mstg-opc-i-ocss-bp02.js?container_id=buzzsprout-player-9042563&player=small" type="text/javascript" charset="utf-8"></script>

# Spis treści

- [Wprowadzenie](#wprowadzenie)
- [OWASP Web Security Testing Guide](#owasp-web-security-testing-guide)
- [OWASP Mobile Security Testing Guide](#owasp-mobile-security-testing-guide)
- [OWASP Proactive Controls](#owasp-proactive-controls)
- [OWASP Cheat Sheet Series](#owasp-cheat-sheet-series)
- [Podsumowanie](#podsumowanie)
- [Referencje](#referencje)

# Wprowadzenie

Jeszcze przed rozpoczęciem omawiania projektów dobrze byłoby dowiedzieć się czym jest i czym nie jest sam OWASP. Tę kwestię wyjaśniłem na początku odcinka pierwszego, więc jeżeli nie udało Ci się go jeszcze przesłuchać to zachęcam do nadrobienia zaległości.

Natomiast moją ambicją w tym odcinku jest przedstawienie Ci mniej znanych projektów OWASP-a nie wchodząc w szczegóły tak mocno jak ostatnio. Jeżeli jakiś z omawianych projektów wyda Ci się interesujący to wgryzienie się w niego potraktuj jako zadanie domowe.

Podobnie jak w odcinku poprzednim – pod koniec zrobię małe podsumowanie. Wysłuchaj odcinek do końca żeby tego nie przegapić.

# OWASP Web Security Testing Guide

![OWASP Web Security Testing Guide](/public/OWASP_Web_Security_Testing_Guide.png 'OWASP Web Security Testing Guide')

Web Security Testing Guide, czyli WSTG to kompendium wiedzy na temat testowania bezpieczeństwa web aplikacji składające się z 3 części:

* Część pierwsza jest spojrzeniem wysokopoziomowym i opisuje m.in. ogólne wymagania testowania web aplikacji, zakres testowania, zasady oraz techniki testowania, najlepsze praktyki dla raportowania oraz przypadki biznesowe dla testowania,
* Część druga wprowadza OWASP Testing Framework, czyli sposób w jaki można podejść do implementacji procesu testowania oprogramowania w trakcie SDLC i —co ważne— nie ogranicza się tutaj do pojedynczej fazy tylko omawia różne sposoby w różnych fazach SDLC,
* A część trzecia wprowadza OWASP Web Application Security Testing Methodology, czyli konkretną metodykę testowania web aplikacji pod kątem bezpieczeństwa (dla przykładu – jak sprawdzić czy aplikacja jest podatna na SQL Injection?).

Najnowsza wersja WSTG to wersja 4.2 wydana w grudniu poprzedniego roku (to jest roku 2020). Natomiast pierwsza wersja wyszła 16 lat wcześniej, czyli w roku 2004 pod nazwą OWASP Testing Guide, skracanym do OTG.

Różne role biorące udział w procesie wytwórczym mogą wykorzystać WSTG na różne sposoby:

* Programiści mogą użyć WSTG jako bazy do stworzenia testów jednostkowych weryfikujących odpowiednie właściwości systemu,
* Testerzy QA mogą użyć WSTG do rozbudowania własnego warsztatu testerskiego o testowanie bezpieczeństwa,
* Bezpiecznicy mogą użyć WSTG jako głównej bazy swoich działań w testowaniu bezpieczeństwa web aplikacji,
* A menedżerzy, projektanci czy liderzy do zrozumienia w jaki sposób testowanie bezpieczeństwa pasuje do procesu wytwórczego oprogramowania.

Autorzy WSTG wielokrotnie zwracają uwagę na to, że organizacje powinny dokonać przeglądu aktywności wykonywanych w procesie wytwórczym i zagwarantować, że bezpieczeństwo ma swoje miejsce na każdym etapie procesu SDLC. Ja podpisuję się pod tym rękoma i nogami, sam powtarzam to od lat.

Dodatkowo im wcześniej wykryjemy problem tym szybciej i taniej jesteśmy w stanie go naprawić. Deweloperzy i testerzy QA powinni być pierwszą i główną linią dbania o bezpieczeństwo aplikacji. Rolą bezpiecznika jest im pomóc (ta pomoc może przyjąć różne formy m.in. edukację, rekomendacje, konsultacje).

Zaprezentowany w dokumencie OWASP Testing Framework zawiera opis aktywności, które powinny zadziać się na każdym etapie procesu wytwórczego: Przed rozpoczęciem budowania, a następnie w czasie projektowania, budowania, deploymentu oraz utrzymania.

W WSTG można również znaleźć opis 4 podstawowych sposobów oceny bezpieczeństwa web aplikacji. Są nimi:

* Przegląd manualny (tutaj chodzi o audyt rozwiązania),
* Modelowanie zagrożeń,
* Przegląd kodu,
* Testy penetracyjne.

Autorzy opisują bardziej szczegółowo każdy z tych sposobów podając jego plusy i minusy. Ja te opisy tutaj pominę z wyjątkiem kilku uwag do testów penetracyjnych.

Czemu? Wiele organizacji próbuje robić pentesty dla swoich web aplikacji co moim zdaniem —oraz zdaniem autorów WSTG— jest po prostu nieoptymalne. Testy penetracyjne mają swoje miejsce w procesie wytwórczym, ale jest ono bardzo wąskie i przynosi mniej korzyści niż ocena podatności. Należy pamiętać, że to są dwa różne od siebie rodzaje testowania mające różne cele, a co za tym idzie również różny zwrot z inwestycji <sup id="fnref:1"><a href="#fn:1">1</a></sup>.

<div class="message">
Sam Gary McGraw (dla niewtajemniczonych ojciec bezpieczeństwa oprogramowania) lata temu pisał, że "W praktyce testy penetracyjne mogą zidentyfikować jedynie małą próbkę wszystkich możliwych problemów bezpieczeństwa w systemie". Ja podpisuję się pod tym znowu rękoma i nogami.
</div>

Podoba mi się również zwięzła ocena pentestów względem procesu wytwórczego, która brzmi następująco: *za mało i za późno*.

Każdy test powinien kończyć się powstaniem artefaktu w postaci raportu. Sama forma jest tutaj dowolna, ale dobry raport powinien zawierać kilka kluczowych informacji:

* Co było testowane?
* Przez kogo?
* Kiedy?
* Na jakiej wersji aplikacji? (Idealnie jeżeli jest to git commit)

Natomiast znalezione problemy powinny posiadać szczegółowe opisy wraz z Proof-of-Concept możliwymi do odtworzenia przez innych ludzi w zespole (w tym developera). O ile jest to możliwe powinien być wskazany konkretny punkt wystąpienia podatności (np. punkt końcowy lub funkcja w kodzie jeżeli mamy dostęp do źródeł).

Poza tym raport powinien również identyfikować interesariusza biznesowego – testowanie nie odbywa się w próżni, celem jest znalezienie problemów i wyprowadzenie tych, które są dla nas nieakceptowalne. Żeby tego dokonać interesariusz biznesowy musi zrozumieć ryzyko i zaplanować działania naprawcze.

Rekomendowanym w WSTG podejściem do testowania bezpieczeństwa jest posiadanie kontroli bezpieczeństwa na każdym etapie SDLC: Od audytów i modelowania zagrożeń podczas fazy projektowej, przez zintegrowanie narzędzi automatycznych w potoku CICD, aż do testów manualnych wykonywanych przez specjalistów.

Ważna uwaga: Narzędzia automatyczne nigdy nie będą efektywne w 100%. Nieważne czy mówimy o SAST czy DAST. Cytując Michaela Howarda "Narzędzia nie czynią oprogramowania bezpiecznym. Narzędzia pomagają skalować proces oraz zapewniać wyrównanie z politykami bezpieczeństwa". Tyle i aż tyle.

Na uwadze należy mieć również to, że narzędzia są generyczne, to znaczy, że nie są dostosowane do Twojej aplikacji. Z tej racji zawsze będą w stanie wykryć tylko pewien podzbiór podatności, który można zgeneralizować dla wszystkich aplikacji. Natomiast z doświadczenia wiem, że najpoważniejsze problemy bezpieczeństwa rzadko kiedy są generyczne i najczęściej wynikają z logiki biznesowej oraz projektu architektury.

Dodatkowym problemem z narzędziami automatycznymi jest duża ilość tzw. False Positives, czyli znalezisk, które nie są faktycznymi problemami bezpieczeństwa, a na których weryfikacje musimy poświęcić czas i energię. W takim wypadku jeżeli naszym celem jest znalezienie najbardziej krytycznych podatności to powinniśmy się zastanowić czy automaty są odpowiednią inwestycją czy jednak testowanie manualne powinno mieć wyższy priorytet.

Oczywiście automaty mają swoje miejsce i używane z głową działają jako świetna pomoc przy zapewnianiu bezpieczeństwa.

Natomiast przechodząc do OWASP Web Application Security Testing Methodology, WSTG definiuje testowanie jako proces porównywania stanu systemu lub aplikacji ze zbiorem kryteriów.

Autorzy trafnie punktują, że bezpieczeństwo często testowane jest w odniesieniu do mentalnych kryteriów testera – to znaczy, że nie ma ogólnie przyjętej definicji takich kryteriów co prowadzi do braku spójności oraz kompletności w testowaniu. Ma to również wpływ na to, że testowanie bezpieczeństwa często postrzegane jest jako "sztuka tajemna".

Jednym z celów WSTG jest stworzenie takich kryteriów oraz odczarowanie testowania bezpieczeństwa jako czegoś co jest dostępne tylko dla wtajemniczonych. Na koniec dnia testowanie bezpieczeństwa systemu IT (nie ważne czy mówimy tu o ocenie podatności czy teście penetracyjnym) to zwykła część Quality Assurance.

Oczywiście testowanie bezpieczeństwa nigdy nie będzie w 100% naukowe i zawsze będzie posiadało pewien element sztuki zależny od kreatywności testera, jednak sformalizowanie podejścia do testowania zmniejsza chaotyczność przez co poprawia długoterminową skuteczność.

Ważnym faktem jest to, że zaprezentowana metodyka zbudowana jest wokół podejścia black-box, czyli z minimalną informacją na temat testowanej aplikacji oraz wprowadza podział na testowanie pasywne i aktywne <sup id="fnref:2"><a href="#fn:2">2</a></sup>. Często sam pasywny test może nam już dużo powiedzieć o danej aplikacji.

WSTG zawiera praktyczne, techniczne opisy tego jak testować właściwości bezpieczeństwa aplikacji. Opisy zgrupowane są w obszary testowania:

* Zbieranie informacji,
* Testowanie konfiguracji, zarządzania tożsamością, uwierzytelniania, autoryzacji, zarządzania sesją, obsługi danych wejściowych, obsługi błędów, kryptografii, logiki biznesowej oraz strony klienckiej (client-side).

Z tej listy tylko pierwszy obszar (czyli zbieranie informacji) jest testowaniem pasywnym, każdy kolejny rodzaj to testowanie aktywne.

Te rodzaje testowania mapują się dość dobrze do obszarów wymienionych w ASVS <sup id="fnref:3"><a href="#fn:3">3</a></sup>. Nie jest to mapowanie 1-1, ale i tak jest przydatne. Dzięki temu mapowaniu WSTG można używać jako materiału pomocniczego do testów skorelowanych z wytycznymi ASVS.

<div class="message">
WSTG nie powinien być widziany jako checklista. WSTG sprawdzi się świetnie jako fundament warsztatu testerskiego, który musi być cały czas rozwijany.
</div>

A jak wygląda przykładowy opis zawarty w tej metodyce? Weźmy na przykład Insecure Direct Object Reference, znany jako IDOR. Co w nim znajdziemy? Ano znajdziemy tam:

* Sekcję podsumowanie opisującą z grubsza o co chodzi w tym problemie,
* Sekcję opisującą cel danego przypadku testowego,
* Sekcję opisującą jak konkretnie testować aplikację pod kątem tej podatności,
* Oraz sekcję z referencjami.

W załącznikach do dokumentu można również znaleźć listę narzędzi, rekomendowane książki oraz krótki opis tego jak można wykorzystać DevTools wbudowane w przeglądarki do testowania w momencie kiedy nie mamy nic innego pod ręką.

Na koniec powiem, że w dokumencie znalazłem 2 ciekawe fakty statystyczne:

1. Konsorcjum do sprawy jakości oprogramowania oszacowało, że koszt związany z niską jakością aplikacji w roku 2018 wyniósł prawie 3 tryliony dolarów. Nie wchodziłem głębiej w źródła danych, ale liczba powala rozmiarem,
2. Estymowany koszt pojedynczego biuletynu bezpieczeństwa firmy Microsoft wynosi 100,000 USD. Dane są z połowy lat 2000 więc dzisiaj ten koszt jest na pewno większy.

# OWASP Mobile Security Testing Guide

Mobile Security Testing Guide, czyli MSTG to poradnik omawiający sposoby testowania bezpieczeństwa aplikacji mobilnych.

Od razu zaznaczę, że MSTG jest dużo mniej szczegółowy w podejściu niż WSTG – w zasadzie MSTG skupia się tylko na metodyce testowania implementacji, a nie na wysokopoziomowym spojrzeniu na to jak stworzyć spójny framework testowania bezpieczeństwa w organizacji.

Pierwsza wersja MSTG ujrzała światło dzienne w roku 2017 —czyli nie tak dawno— a najnowsza wersja 1.2 jest z lipca roku 2021.

MSTG żyje w mocnej symbiozie z Mobile Application Security Verification Standard (MASVS), czyli bratem ASVS-a dla aplikacji mobilnych.

Na czym ta symbioza dokładnie polega? MASVS opisuje model bezpieczeństwa aplikacji mobilnych i listuje dla nich generyczne kontrolki bezpieczeństwa. Te kontrolki mogą posłużyć do zbudowania wymagań funkcjonalnych i niefunkcjonalnych. Natomiast MSTG opisuje sposoby weryfikowania kontrolek zawartych w MASVS dostarczając testerom potrzebne *know-how*.

W przeciwieństwie do Web Security Testing Guide, tutaj mamy zmapowanie w 100% pomiędzy MSTG a MASVS.

A jakie obszary zostały omówione? MSTG najpierw omawia ogólne podejście do testowania m.in. wprowadzając taksonomię aplikacji mobilnych oraz omawiając sposoby testowania bezpieczeństwa, sposoby na debugowanie i inżynierię odwrotną, architektury uwierzytelniania, komunikację sieciową, kryptografię, jakość kodu i interfejs użytkownika.

Następnie MSTG przechodzi do szczegółowego opisu tego jak testować bezpieczeństwo aplikacji mobilnych na platformach iOS oraz Android

Na końcu dokumentu znajdziemy również opis narzędzi testerskich oraz sugerowane dalsze lektury.

W liście współautorów MSTG jest smaczek w postaci Pawła Rzepy, szerzej znanego z pracy nad bezpieczeństwem chmury AWS. Paweł jeżeli tego słuchasz to pozdrawiam, a my lecimy dalej!

# OWASP Proactive Controls

Top 10 Proactive Controls —w skrócie OPC— to lista kontroli bezpieczeństwa, które powinny zostać rozważone podczas wytwarzania dowolnego projektu oprogramowania. Najnowszą wersją Proactive Controls jest wersja trzecia z 2018 roku.

Głównym odbiorcą Proactive Controls są deweloperzy, ale menedżerowie, product ownerzy, inżynierzy QA i inne role uczestniczące w procesie wytwórczym również skorzystają na znajomości tego dokumentu ponieważ OPC dostarcza konkretne i praktyczne porady o tym jak wytwarzać bezpieczne oprogramowanie.

Autorzy jasno zaznaczają, że omawiane kontrole powinny być implementowane jak najwcześniej w cyklu wytwórczym, aby zmaksymalizować ich skuteczność. Tym samym propagują podejście "Shift Left" polegające na przesuwaniu bezpieczeństwa do wcześniejszych faz w procesie wytwórczym takich jak faza implementacji czy faza projektowania.

Ponadto autorzy nie kryją się z tym, że OPC jest na bardzo podstawowym poziomie szczegółowości i jego rolą jest bycie punktem startowym w działaniach bezpieczeństwa aplikacji.

Top 10 Proactive Controls są podobne do OWASP Top 10 <sup id="fnref:4"><a href="#fn:4">4</a></sup>. W zasadzie można na nie popatrzeć jako pewnego rodzaju odbicie lustrzane, gdzie Top 10 mówi o słabościach, a OPC mówi o sposobach obrony przed wynikającymi ze słabości podatnościami.

Co więcej każda kontrola zawarta w OPC mapuje się do jednego lub wielu problemów z listy OWASP Top 10. Informacja o zmapowaniu znajduje się na końcu opisu każdej kontroli.

A jakie kontrole wchodzą w skład najnowszej wersji dokumentu?

* Kontrola 1: Zdefiniuj wymagania bezpieczeństwa,
* Kontrola 2: Wykorzystaj frameworki i biblioteki bezpieczeństwa dostępne w Twoim stosie technologicznym
<div class="message">
Coś co powtarzam od lat. Nie wymyślaj koła na nowo, poznaj swój framework i używaj dostępnych mechanizmów bezpieczeństwa. Dla przykładu Rails Guides mają świetny rozdział o bezpieczeństwie, który polecam przeczytać nawet jak nie jesteś railsowcem.
</div>
* Kontrola 3: Zabezpiecz dostęp do bazy danych,
* Kontrola 4: Enkoduj i Eskejpuj Dane Wejściowe,
* Kontrola 5: Waliduj Wszystkie Dane Wejściowe,
<div class="message">
Nie próbuj danych oczyszczać, jeżeli walidacja się nie powiedzie to bezpieczniej jest dane odrzucić i poinformować o tym użytkownika.
</div>
* Kontrola 6: Zaimplementuj tożsamość cyfrową (tj. Implement Digital Identity),
* Kontrola 7: Stosuj i przestrzegaj kontroli dostępu (to się łączy mocno z kontrolą poprzednią – żeby kontrolować dostęp musimy mieć tożsamość),
* Kontrola 8: Chroń dane wszędzie (tj. zarówno "w locie", czyli w kanale komunikacyjnym jak i "w spoczynku", czyli na systemie plików lub w bazie danych),
* Kontrola 9: Zaimplementuj logowanie i monitorowanie pod kątem bezpieczeństwa,
* Kontrola 10: Obsługuj wszystkie błędy i wyjątki.

Każda kontrola zawiera następujące elementy:

* Szczegółowy opis zawierający best practices do rozważenia przez dewelopera,
* Opis implementacji danej kontroli włącznie z przykładami,
* Listę podatności jakie dana kontrola mityguje (mapa do m.in. Top 10 i CWE),
* Listę referencji do dalszego zgłębienia tematu we własnym zakresie (np. do Cheat Sheet Series, o którym będę mówił za chwilę),
* Oraz listę narzędzi, które mogą ułatwić wprowadzenie danej kontroli do Twojej aplikacji.

Proactive Controls mogą służyć za bazę dla szkolenia *hands-on* z bezpieczeństwa aplikacji dla deweloperów i architektów. I moim zdaniem faktycznie sprawdzą się tutaj lepiej niż Top 10, który pasuje bardziej do szkolenia z etycznego hackingu dla testerów QA lub bezpieczników.

Autorzy w wielu miejscach odnoszą się do innych projektów OWASP-a i tego w jaki sposób mogą one posłużyć do zgłębienia tematu. Dla przykładu:

* Żeby zrozumieć słabości i podatności warto poznać OWASP Top 10,
* Do implementacji kontroli zawartych w Proactive Controls, można użyć OWASP ASVS lub MASVS,
* Natomiast żeby dowiedzieć się w jaki sposób wbudować bezpieczeństwo w proces wytwórczy można przejść do projektu OWASP SAMM.

I z tej racji przypominam, że w [poprzednim odcinku omówiłem szczegółowo projekty Top 10, ASVS i SAMM](/owasp-top10-asvs-samm/){:target="_blank"} więc jeżeli jeszcze nie udało Ci się go przesłuchać to do tego zachęcam.

# OWASP Cheat Sheet Series

![OWASP Cheat Sheet Series](/public/OWASP_Cheat_Sheet_Series_logo.png 'OWASP Cheat Sheet Series')

Cheat Sheet Series to zbiór dokumentów —tak zwanych ściągawek— zawierających opisy dobrych praktyk bezpieczeństwa dla deweloperów, architektów i bezpieczników.

Zamiast skupiać się na szczegółowym opisywaniu problemów, które często jest mało pomocne dla osób niezwiązanych z bezpieczeństwem, autorzy postawili na dokumentację praktycznych porad, które większość deweloperów czy architektów będzie w stanie użyć w swojej pracy.

<div class="message">
Podoba mi się motto projektu, które brzmi "Life is too short, AppSec is tough, cheat!", czyli w wolnym tłumaczeniu "Życie jest krótkie, bezpieczeństwo aplikacji jest trudne, ściągaj!".
</div>

Projekt w wersji 1 powstał w roku 2014 i był hostowany w OWASP-owej wiki aż do roku 2018. Następnie w roku 2019 został podbity do oficjalnej wersji drugiej i dalszy jego rozwój został przeniesiony w całości na GitHub.

Ważną informacją jest to, że Cheat Sheet Series są w ciągłym rozwoju. To znaczy, że cały czas pojawiają się nowe ściągawki oraz uaktualnienia do tych już istniejących. W chwili nagrywania tego odcinka, czyli w sierpniu 2021 roku seria zawiera 74 ściągawki stworzone przez specjalistów posiadających wiedzę ekspercką na tematy, które opisują.

Kolejnym ważnym faktem jest pomost zbudowany pomiędzy projektami Proactive Controls (o którym mówiłem wcześniej) oraz Application Security Verification Standard (o którym mówiłem [w odcinku poprzednim](/owasp-top10-asvs-samm/){:target="_blank"}).

Jak ten pomost konkretnie wygląda?

* Jeżeli dla jakiejś kontrolki z Proactive Controls lub ASVS brakuje ściągawki to taka ściągawka wpada do backloga, a następnie w momencie powstania jest linkowana w tych projektach,
* Natomiast jeżeli ściągawka istnieje, ale nie posiada odpowiednich informacji pomagających z daną kontrolką ASVS lub Proactive Controls to ściągawka jest aktualizowana tak, żeby była wyrównana z tymi dokumentami.

Z tą symbiozą pomiędzy Cheat Sheet Series, Proactive Controls oraz ASVS związane są również 3 różne widoki. Mam na myśli tutaj to, że ściągawki można przeglądać na 3 różnych listach:

* Lista w widoku ogólnym, czyli alfabetycznym. Dodatkowo, ten widok uwzględnia ikonkę technologii na jakiej omawia przykłady lub rozwiązania problemów,
* Lista w widoku podzielonym względem Proactive Controls,
* Oraz lista w widoku podzielonym względem ASVS.

No dobra, a co ja w tych ściągawkach w ogóle znajdę? Poziom abstrakcji poszczególnych ściągawek jest zróżnicowany. Znajdziemy takie, które omawiają konkretne problemy implementacyjne jak obrona przed OS Command Injection czy SQL Injection, ale również bardziej ogólne omawiające najlepsze praktyki dla funkcjonalności (przykładowo dla uploadu plików) czy architektury rozwiązania (przykładowo Bezpieczeństwo Mikroserwisów). I tak jak powiedziałem wcześniej, obecnie projekt zawiera 74 ściągawki, więc jest tego całkiem sporo.

<div class="message">
Jako bezpiecznik sam często używam Cheat Sheet Series jako pierwszy krok podczas rekonesansu tematów, z którymi nie miałem wcześniej styczności.
</div>

A na zakończenie wspomnę o kolejnym polskim akcencie. Mianowicie jednym z liderów Cheat Sheet Series jest polak – Jakub Maćkowski. Jakubie, jeżeli słuchasz tej audycji to serdecznie pozdrawiam!

# Podsumowanie

A teraz czas na podsumowanie tego wszystkiego co zostało powiedziane.

WSTG pomaga organizacjom w testowaniu ich web aplikacji po to, aby budować bezpieczne oprogramowanie. Celem WSTG jest pomoc ludziom w zrozumieniu "Co? Czemu? Kiedy? Gdzie? i Jak?" testować w web aplikacjach pod kątem bezpieczeństwa.

* Pierwsza część, czyli OWASP Testing Framework wycelowana jest raczej w architektów bezpieczeństwa i ról powyżej (np. CISO),
* Natomiast druga część, czyli metodyka wycelowana jest głównie w osoby zajmujące się pracą operacyjną – bezpieczników, testerów QA oraz deweloperów.

WSTG można użyć jako podstawy do zbudowania własnych programów testowania bezpieczeństwa aplikacji czy to w organizacji czy jako podwykonawca.

MSTG jest odpowiednikiem WSTG, ale dla aplikacji mobilnych. Jego zakres jest węższy i skupia się wokół samej metodyki testowania, którą opisuje ogólnie oraz dla obu flagowych platform — Androida i iOS.

MSTG jest zmapowany z MASVS w 100% więc można go użyć do weryfikacji wymagań opartych o MASVS.

MSTG jest napisany z myślą o testerach, ale deweloperzy aplikacji mobilnych również mogą skorzystać na tej wiedzy, jednak MASVS może być dla nich lepszym pierwszym krokiem.

Top 10 Proactive Controls to lista top 10 kontroli bezpieczeństwa, które powinny być wbudowane w każdą web aplikację. OPC posiada mapowanie do problemów bezpieczeństwa, które możesz znaleźć w OWASP Top 10. Głównym odbiorcą OPC są osoby techniczne odpowiedzialne za projektowanie i budowanie aplikacji.

Cheat Sheet Series to zestaw ściągawek opisujący najlepsze praktyki do rozwiązywania problemów bezpieczeństwa. Na chwilę obecną ściągawek jest 74, a ich poziom abstrakcji jest zróżnicowany – są zarówno takie bliższe implementacji jak i takie, które dotyczą architektury. Z uwagi na to odbiorcami OCSS są osoby techniczne na każdym poziomie – od juniora do architekta.


<div class="footnotes">
  <ol>
    <li class="footnote" id="fn:1">
      <p>Testy penetracyjne jako jeden z rodzajów oceny bezpieczeństwa są tematem <a href="https://bezpiecznykod.pl/bp08" target="_blank">odcinka ósmego</a>. <a href="#fnref:1" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:2">
      <p>Black-box oraz inne rodzaje podejść zostały omówione w <a href="https://bezpiecznykod.pl/bp05" target="_blank">odcinku piątym</a>. <a href="#fnref:2" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:3">
      <p>ASVS, czyli Application Security Verification Standard został omówiony w <a href="/owasp-top10-asvs-samm/" target="_blank">odcinku pierwszym</a>. <a href="#fnref:3" title="powrót do artykułu"> ↩</a></p>
    </li>
    <li class="footnote" id="fn:4">
      <p>Lista OWASP Top 10 została omówiona w <a href="/owasp-top10-asvs-samm/" target="_blank">odcinku pierwszym</a>. <a href="#fnref:4" title="powrót do artykułu"> ↩</a></p>
    </li>
  </ol>
</div>

# Referencje

Omawiane projekty OWASP i inne:

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/){:target="_blank"}{:target="_blank"}
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/){:target="_blank"}
- [OWASP Mobile Application Security Verification Standard](https://github.com/OWASP/owasp-masvs){:target="_blank"}
- [OWASP Top 10 Proactive Controls](https://owasp.org/www-project-proactive-controls/){:target="_blank"}
- [OWASP Cheat Sheet Series](https://owasp.org/www-project-cheat-sheets/){:target="_blank"}
    - [Lista - widok ogólny](https://cheatsheetseries.owasp.org/Glossary.html){:target="_blank"}
    - [Lista - podzielona względem Proactive Controls](https://cheatsheetseries.owasp.org/IndexProactiveControls.html){:target="_blank"}
    - [Lista - podzielona względem ASVS](https://cheatsheetseries.owasp.org/IndexASVS.html){:target="_blank"}
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/){:target="_blank"}
- [Ruby on Rails Guides - Security](https://guides.rubyonrails.org/security.html){:target="_blank"}
- [Gary McGraw](https://en.wikipedia.org/wiki/Gary_McGraw){:target="_blank"}
- [Michael Howard](https://en.wikipedia.org/wiki/Michael_Howard_(Microsoft)){:target="_blank"}
- [Shift Left Testing](https://en.wikipedia.org/wiki/Shift-left_testing){:target="_blank"}
