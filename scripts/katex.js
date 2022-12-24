hexo.extend.filter.register("markdown-it:renderer", function (md) {
  md.use(require("markdown-it-texmath"), {
    engine: require("katex"),
    delimiters: "dollars",
  });
});

hexo.extend.filter.register("after_render:html", function (html) {
  const linkTag =
    '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.4/dist/katex.min.css" integrity="sha384-vKruj+a13U8yHIkAyGgK1J3ArTLzrFGBbBc0tDp4ad/EyewESeXE/Iv67Aj8gKZ0" crossorigin="anonymous">';

  return html.replace(/(<\/head>)/i, linkTag + "$1");
});
