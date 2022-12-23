hexo.extend.filter.register('markdown-it:renderer', function(md) {
  var twemoji = require('twemoji');

  md.renderer.rules.emoji = function(token, idx) {
    return twemoji.parse(token[idx].content);
  };
});
