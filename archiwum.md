---
layout: page
title: Archiwum
permalink: /archive/
---

{% for post in site.posts %}
<article>
  <h3><a href="{{ post.url }}">{{ post.title }} – <small>{{ post.date | date: "%d/%m/%Y" }}</small></a></h3>
</article>
{% endfor %}