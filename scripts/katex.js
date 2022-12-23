hexo.extend.filter.register("markdown-it:renderer", function(md) {
  md.use(
    require("markdown-it-texmath"),
    {
      engine: require("katex"),
      delimiters:"dollars",
    }
  );
});

hexo.extend.filter.register('after_render:html', function (html) {
  const linkTag = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.12.0/dist/katex.min.css" integrity="sha384-AfEj0r4/OFrOo5t7NnNe46zW/tFgW6x/bCJG8FqQCEo3+Aro6EYUG4+cU+KJWu/X" crossorigin="anonymous">'

  return html.replace(
    /(<\/head>)/i,
    linkTag + "$1",
  );
});
