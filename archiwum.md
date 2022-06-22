---
layout: page
title: Archiwum
permalink: /archive/
---

{% for post in site.posts %}
<article>
  <small>{{ post.date | date: "%d/%m/%Y" }}</small> – <a href="{{ post.url }}">{{ post.title }}</a>
</article>
{% endfor %}