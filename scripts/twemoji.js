hexo.extend.filter.register("markdown-it:renderer", function (md) {
  const twemoji = require("twemoji");

  md.renderer.rules.emoji = function (token, idx) {
    return twemoji.parse(token[idx].content, {
      // ref. https://github.com/twitter/twemoji/issues/580
      base: "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/",
    });
  };
});
