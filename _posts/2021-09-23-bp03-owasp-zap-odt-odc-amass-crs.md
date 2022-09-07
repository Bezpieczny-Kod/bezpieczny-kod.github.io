---
layout: post
author: Andrzej Dyjak
title: Narzędzia techniczne OWASP, które warto mieć w swoim arsenale
description: Transkrypcja w formie artykułu trzeciego odcinka podcastu Bezpieczna Produkcja, w którym opowiedziałem o najciekawszych narzędziach technicznych ze stajni OWASP-a – Zed Attack Proxy (ZAP), Dependency Track & Check (ODT, ODC), Amass oraz ModSecurity Core Rule Set (CRS).
permalink: /owasp-zap-odt-odc-amass-crs/
---

Transkrypcja w formie artykułu trzeciego odcinka podcastu [Bezpieczna Produkcja](https://bezpiecznykod.pl/podcast), w którym opowiedziałem o najciekawszych narzędziach technicznych ze stajni OWASP-a – Zed Attack Proxy (ZAP), Dependency Track & Check (ODT, ODC), Amass oraz ModSecurity Core Rule Set (CRS).

<!--more-->

Odcinek możesz przesłuchać poniżej lub na wszystkich większych platformach, m.in. [Spotify](https://bezpiecznykod.pl/spotify), [Apple Podcasts](https://bezpiecznykod.pl/apple) czy [Google Podcasts](https://bezpiecznykod.pl/google).

<div id="buzzsprout-player-9042563"></div><script src="https://www.buzzsprout.com/1667851/9042563-inne-projekty-owasp-warte-poznania-czyli-krotko-o-wstg-mstg-opc-i-ocss-bp02.js?container_id=buzzsprout-player-9042563&player=small" type="text/javascript" charset="utf-8"></script>

# Spis treści

- [Wprowadzenie](#wprowadzenie)
- [OWASP Zed Attack Proxy](#owasp-zed-attack-proxy)
- [OWASP Dependency Track & Dependency Check](#owasp-dependency-track--dependency-check)
- [OWASP Amass](#owasp-amass)
- [OWASP ModSecurity Core Rule Set](#owasp-modsecurity-core-rule-set)
- [Referencje](#referencje)

# Wprowadzenie

W [odcinku pierwszym](/owasp-top10-asvs-samm/) omówiłem flagowe projekty OWASP, czyli Top 10, Application Security Verification Standard oraz Software Assurance Maturity Model. 

Natomiast w [odcinku drugim](/owasp-wstg-mstg-opc-ocss/) omówiłem mniej znane, ale równie ważne projekty takie jak Web Security Testing Guide, Mobile Security Testing Guide, Top 10 Proactive Controls oraz Cheat Sheet Series.

Jeżeli to co przed chwilą powiedziałem nie mówi Ci totalnie nic to dobrze byłoby zacząć od przesłuchania odcinków poprzednich.

Dzisiaj natomiast omówię moje ulubione narzędzia techniczne ze stajni OWASP-a i tym akcentem zamykam OWASP-ową epopeję.

Oczywiście gadać możemy sobie ile chcemy, ale zrozumienie bierze się z działania. Mam nadzieję, że ten odcinek zainspiruje Cię do przeklikania tych narzędzi we własnym zakresie — życzę Ci owocnych łowów!

# OWASP Zed Attack Proxy

![OWASP Zed Attack Proxy](/public/OWASP_ZAP_Banner.png 'OWASP Zed Attack Proxy')

OWASP Zed Attack Proxy —czyli ZAP, bo w zasadzie nikt nie używa pełnej nazwy— jest darmowym skanerem web aplikacji o otwartym kodzie źródłowym. Na nieszczęście ZAP napisany jest w Javie, ale na szczęście to koniec jego minusów. Ok, suche żarty na bok.

ZAP-a można używać zarówno w wydaniu manualnym jak i automatycznym. A więc ZAP przyda się wtedy kiedy tester ma za zadanie przetestować bezpieczeństwo web aplikacji (np. pod kątem WSTG, o którym mówiłem w [odcinku poprzednim](/owasp-wstg-mstg-opc-ocss/)) jak i wtedy kiedy chcemy wbudować podstawowe skany bezpieczeństwa w potok CICD.

A jak to konkretnie działa? ZAP jest narzędziem typu proxy – w wydaniu manualnym tester wpina go pomiędzy przeglądarkę a web aplikację przez co jest w stanie rejestrować całość pętli zapytanie-odpowiedź. Dzięki temu może w prosty sposób modyfikować wysyłane dane takie jak nagłówki czy parametry.

<div class="message">
Jako przeglądarkę do testów polecam Firefoxa (ja korzystam z edycji dla deweloperów) – nie będę wchodził w szczegóły czemu, ale sprawdza się do tego lepiej niż konkurencja. Dodatkowo, polecam plugin Foxy Proxy do żonglowania ustawieniami proxy wewnątrz Firefoxa. Linki do obu narzędzi dodam w notatkach więc nie musisz googlować.
</div>

ZAP posiada wbudowaną listę typowych ataków więc w zasadzie można go puścić na web aplikację bez większego wysiłku i zobaczyć co w trawie piszczy. Kiedyś widziałem prezentację z Mozilli o tym w jaki sposób automatyzacja podstawowego skanu bezpieczeństwa z ZAP-a w CICD pomogła im wykryć dużą ilość podatności przed trafieniem na produkcję <sup id="fnref:1"><a href="#fn:1">1</a></sup>.

Oczywiście rozmawiając o ZAP-ie nie można pominąć jego komercyjnego konkurenta, jego *arch nemesis*, czyli Burpa, który również —NIESTETY— jest napisany w Javie.

Oba narzędzia są do siebie podobne i działają w zasadzie tak samo – cokolwiek da się zrobić w Burpie da się też zrobić w ZAP-ie. Natomiast siła Burpa tkwi w jego ekosystemie – Burp jako pewnego rodzaju gold standard na rynku ma po prostu dużo więcej przydatnych w pracy pluginów. Jednak poza tym ZAP nie jest wcale gorszym rozwiązaniem, a są nawet miejsca, gdzie błyszczy bardziej.

Wcześniej wspomniałem o możliwości automatyzacji ZAP-a – warto również wypunktować, że twórca i główny deweloper ZAP-a w chwili obecnej działa full-time w startupie StackHawk, który używa ZAP-a jako silnika do ichniejszej analizy dynamicznej, a to zapewnia ciągły rozwój narzędzia, bo jest ku temu powód biznesowy.

O Zapie to tyle i przechodzimy do skanowania podatności w zależnościach.

# OWASP Dependency Track & Dependency Check

![OWASP Dependency Track](/public/OWASP_Dependency_Track.png 'OWASP Dependency Track')

OWASP Dependency Track to narzędzia klasy Software Component Analysis —w skrócie SCA— pozwalające na identyfikację oraz redukcję ryzyka związanego z komponentami zewnętrznymi. Przez komponent zewnętrzny mam tutaj na myśli po prostu pakiety/biblioteki dodawane przez menedżery pakietów np. NPM w JS czy Composer w PHP.

Dependency Track pozwala na stworzenie tzw. Software Bill of Materials (SBOM) dla całego portfolio aplikacji wytwarzanych w danej organizacji. Mając SBOM wiemy z jakich komponentów składają się nasze aplikacje i możemy użyć tej informacji do skanowania ich pod różnym kątem. W przypadku Dependency Track mamy do dyspozycji następujące skany:

- Po pierwsze: Skan podatności używanych komponentów trzecich,
<div class="message">
Tutaj nadmienię od razu, że narzędzia klasy SCA nie szukają podatności w kodzie —tak jak robi to SAST— tylko weryfikują czy to czego używamy posiada publicznie znane podatności.
</div>
- Po drugie: Skan aktualności, co stoi w zasadzie obok skanu podatności; czyli informacja czy to czego używamy jest w najnowszej wersji,
- Po trzecie: Skan licencji używanych przez komponenty trzecie. Ten wątek jest ważny w pewnych sytuacjach np. jeżeli działasz w software housie to wiedza na temat licencji sprzedawanego oprogramowania jest kluczowa z punktu widzenia prawnego,
- Oraz po czwarte i ostatnie: Skanowanie tożsamości oraz integralność użytych paczek.

Dependency Track wspiera wszystkie główne stosy technologiczne, czyli:

- PHP-a poprzez wsparcie dla Composera,
- Ruby-iego poprzez wsparcie dla Gemsów,
- Javę poprzez wsparcie dla Mavena,
- .NET-a poprzez wsparcie dla NuGeta,
- JavaScript poprzez wsparcie dla NPM-a,
- oraz Pythona poprzez wsparcie dla PyPI.

OWASP Dependency Check to również narzędzie klasy SCA, ale jego funkcjonalności są wycinkiem tego co oferuje Dependency Track. Dependency Check poprzez analizę użytych komponentów zwraca nam jedynie informację o wykrytych podatnościach.

Dla poszczególnych technologii Dependency Check używa dodatkowych narzędzi, konkretnie są to npm audit i RetireJS dla JavaScript-a oraz bundler audit dla Ruby-iego.

Dependency Check można używać z poziomu linii komend jako osobne narzędzie lub poprzez pluginy w potoku CICD.

Dependency Check ma również plugin do SonarQuba co pozwala połączyć wyniki z tego narzędzia z globalną analizą statyczną zapewnianą przez SonarQube.

Główne różnice pomiędzy Dependency Track, a Dependency Check wyglądają następująco:

- Dependency Track to platforma, Dependency Check to osobne narzędzie,
- Dependency Track skanuje BOM generowany przez dany stos (np. Gemfile w Ruby), a Dependency Check skanuje pliki w projekcie przez co ma większą ilość tzw. False Positives,
- Dependency Track ma bardziej precyzyjne informacje odnośnie publicznych podatności niż Dependency Check, co również wpływa na większą ilość tzw. *False Positives* po stronie Dependency Checka.

Warto przypomnieć, że podatności w używanych komponentach to jeden z problemów znajdujących się na liście OWASP Top 10, o której mówiłem szeroko i głęboko w odcinku pierwszym.

Dodatkowo o drugiej stronie tej monety, czyli o atakach na łańcuchy dostawcze mówiłem na kilku konferencjach oraz lipcowym meetupie SecOps. [Link do nagrania na YouTube](https://www.youtube.com/watch?v=rvlIch7Khzk){:target="_blank"} i lecimy do kolejnego narzędzia!

# OWASP Amass

![OWASP Amass](/public/OWASP_Amass.jpeg 'OWASP Amass')

OWASP Amass to narzędzie służące do enumeracji subdomen. Takie działanie jest jednym z wielu, które przeprowadza się podczas fazy rekonesansu, czyli rozpoznania publicznej powierzchni ataku danej organizacji.

Amass wykorzystuje kilka różnych technik zbierania tych informacji, dzięki czemu jego wyniki są zwykle pełniejsze niż konkurencyjnych narzędzi. Między innymi jest to:

- Enumeracja historycznych wpisów DNS,
- Szukanie artefaktów w popularnych wyszukiwarkach takich jak Google, DuckDuckGo, ale również w tych mniej oczywistych zasobach takich jak jak raporty HackerOne,
- Wyciąganie danych ze starych certyfikatów SSL/TLS,
- Odpytywanie różnych źródeł threat intelligence takich jak AlienVault czy VirusTotal,
- Oraz przeszukiwanie historii w archiwizatorach sieci web (np. WayBack Machine).

Narzędzi realizujących podobne zadanie do Amassa jest wiele, ale z mojego doświadczenia Amass bije je na głowę. Co więcej Amass jest cały czas aktywnie rozwijany co przekłada się na jakość wyników.

Polecam mocno pobawić się tym cudem we własnym zakresie (np. puścić go na swoje domeny lub —dla żartu i zerowego profitu— na domenę GOV.pl). Jakby co to spokojna głowa – skany są pasywne więc nic złego się nie stanie. A jak już jesteśmy przy skanowaniu pasywnym to przejdźmy do skanowania aktywnego, a konkretnie do wykrywania i blokowania takich skanów za pomocą kolejnego narzędzia...

# OWASP ModSecurity Core Rule Set

![OWASP ModSecurity Core Rule Set](/public/OWASP_Core_Rule_Set.png 'OWASP ModSecurity Core Rule Set')

OWASP ModSecurity Core Rule Set —w skrócie CRS— to zestaw reguł dla Web Application Firewalla pomagających wykrywać i blokować typowe ataki na web aplikacje.

CRS jest dla konkretnego WAF-a, a mianowicie dla ModSecurity. ModSecurity to wieloplatformowy Web Application Firewall o otwartym kodzie źródłowym dostępny dla web serwerów Apache, Nginx oraz IIS.

A czym jest WAF? WAF to pudełko lub usługa, którą stawiamy przed naszą aplikacją w celu jej obrony. Najczęściej działa to w ten sposób, że WAF pomaga po pierwsze wykrywać i blokować ataki na aplikacje oraz po drugie wdrażać tzw. virtual patching.

Że co? Ok, wejdę jeszcze do tej króliczej nory i powiem czym jest Virtual Patching. Virtual Parching, czyli wirtualne łatki stosuje się wtedy kiedy z jakichś przyczyn nie jesteśmy w stanie wyprowadzić podatności w kodzie aplikacji (np. system jest krytyczny z punktu widzenia biznesowego i nie możemy mieć przestoju). W takim wypadku można dodać logikę na poziomie infrastruktury dla podatnego punktu końcowego tak, żeby użytkownicy nie byli w stanie wykorzystać danej podatności. I stąd nazwa "wirtualna łatka" ponieważ podatność zostaje w kodzie aplikacji.

Najnowsza wersja regułek CRS to wersja 3.3.2.

Jakie typowe ataki możemy wykryć i zablokować używając CRS? CRS pomoże nam w obronie naszych aplikacji przed typowymi problemami z listy OWASP Top 10, czyli:

- SQL Injections,
- Cross-Site Scripting (XSS),
- czy Local oraz Remote File Inclusion.

Poza tym CRS może nam pomóc również z wykryciem oraz zablokowaniem ataków zautomatyzowanych (botów, skryptów, itp.).

Na stronie projektu można znaleźć odnośniki do materiałów edukacyjnych omawiających praktyczną implementację CRS. W notatkach do tego odcinka zamieszczę te najlepsze więc po przesłuchaniu możesz szybko do nich wskoczyć.

A na koniec dodam, że regułki CRS są dostępne we wszystkich WAF-ach największych dostawców chmur – zarówno w AWS, Azure jak i GCP. Linki do opisu u każdego vendora również znajdziesz w notatkach do tego odcinka.


<div class="footnotes">
  <ol>
    <li class="footnote" id="fn:1">
      <p>A konkretnie mówił o tym <a href="https://www.usenix.org/conference/enigma2017/conference-program/presentation/vehent" target="_blank">Julien Vehent na Enigma 2017, slajd 26</a>.<a href="#fnref:1" title="powrót do artykułu"> ↩</a></p>
    </li>
  </ol>
</div>

# Referencje

Omawiane projekty OWASP:

- [OWASP Zed Attack Proxy](https://www.zaproxy.org/){:target="_blank"}
- [OWASP Dependency Track](https://owasp.org/www-project-dependency-track/){:target="_blank"}
    - [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/){:target="_blank"}
    - [OWASP Dependency Track vs Check](https://docs.dependencytrack.org/odt-odc-comparison/){:target="_blank"}
- [OWASP Amass](https://owasp.org/www-project-amass/){:target="_blank"}
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/){:target="_blank"}
    - [Core Rule Set Docs](https://coreruleset.org/docs/){:target="_blank"}
    - [Embedding ModSecurity](https://www.netnea.com/cms/apache-tutorial-6_embedding-modsecurity/){:target="_blank"}
    - [Including OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-7_including-modsecurity-core-rules/){:target="_blank"}
    - [Handling False Positives with the OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/){:target="_blank"}
    - [ModSecurity](https://github.com/SpiderLabs/ModSecurity){:target="_blank"}
    - [Azure CRS](https://docs.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules?tabs=owasp31){:target="_blank"}
    - [AWS CRS](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html){:target="_blank"}
    - [GCP CRS](https://cloud.google.com/armor/docs/rule-tuning){:target="_blank"}

Inne wspomniane projekty:

- [Ty, Twój kod i wasz łańcuch dostawczy](https://www.youtube.com/watch?v=rvlIch7Khzk){:target="_blank"}
- [Mozilla Firefox Developer Edition](https://www.mozilla.org/en-US/firefox/developer/){:target="_blank"}
- [Firefox Plug-in: Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/){:target="_blank"}
