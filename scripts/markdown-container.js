const fs = require("node:fs");
const path = require("node:path");
const { unfurl } = require("unfurl.js");
const jsdom = require("jsdom");

const CACHE_DIR = "ogp-cache";

const containers = [
  {
    /*
      ::: webcard http://example.com
      :::
    */
    name: "webcard",
    options: {
      validate: (params) => params.trim().match(/^webcard\s+(.*)$/),
      render: (tokens, idx) => {
        const token = tokens[idx];
        const isOpening = token.nesting === 1;
        if (isOpening) {
          const m = token.info.trim().match(/^webcard\s+(.*)$/);
          const url = m[1];

          let data = {};
          const cachePath = path.join(
            CACHE_DIR,
            encodeURIComponent(url) + ".json"
          );
          if (fs.existsSync(cachePath)) {
            data = JSON.parse(fs.readFileSync(cachePath));
          } else {
            unfurl(url)
              .catch((e) => {
                console.log(url + ":");
                console.warn(e);
                return {
                  title: "Not Found",
                  description: "Something wrong...",
                };
              })
              .then(async (metadata) => {
                fs.promises.writeFile(cachePath, JSON.stringify(metadata));
              });
          }

          const ogp = {
            title:
              data.open_graph?.title ??
              data.oEmbed?.title ??
              data.twitter_card?.title ??
              data.title ??
              "",
            description:
              data.open_graph?.description ??
              data.twitter_card?.description ??
              data.description ??
              "",
            url: url,
            favicon: data.favicon,
            hostname: new URL(url).hostname,
            imgSrc:
              data.open_graph?.images?.[0]?.url ??
              data.oEmbed?.thumbnails?.[0]?.url ??
              data.twitter_card?.images?.[0]?.url,
          };

          const innerDoc = new jsdom.JSDOM(`
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
              </head>
              <body>
                <div id="outerContent">
                  <div id="content"></div>
                </div>
              </body>
            </html>
          `).window.document;

          const imgSize = 96;

          const createLink = () => {
            const elm = innerDoc.createElement("a");
            elm.setAttribute("href", ogp.url);
            elm.setAttribute("target", "_blank");
            elm.setAttribute("rel", "noopener noreferrer");
            return elm;
          };

          const createImg = () => {
            const imgElm = innerDoc.createElement("img");
            imgElm.setAttribute("src", ogp.imgSrc);
            imgElm.style.width = `${imgSize}px`;
            imgElm.style.height = `${imgSize}px`;
            imgElm.style.objectFit = "cover";
            const linkElm = createLink();
            linkElm.appendChild(imgElm);
            const divElm = innerDoc.createElement("div");
            divElm.style.top = 0;
            divElm.style.right = 0;
            divElm.style.position = "absolute";
            divElm.appendChild(linkElm);
            return divElm;
          };

          const createTitle = () => {
            const titleElm = innerDoc.createElement("h1");
            titleElm.textContent = ogp.title;
            titleElm.style.fontSize = "15px";
            titleElm.style.color = "black";
            titleElm.style.overflow = "hidden";
            titleElm.setAttribute(
              "style",
              titleElm.getAttribute("style") +
                "display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2;"
            );
            const linkElm = createLink();
            linkElm.appendChild(titleElm);
            return linkElm;
          };

          const createDesc = () => {
            const descElm = innerDoc.createElement("div");
            descElm.textContent = ogp.description;
            descElm.style.fontSize = "10px";
            descElm.style.overflow = "hidden";
            descElm.setAttribute(
              "style",
              descElm.getAttribute("style") +
                "display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3;"
            );
            return descElm;
          };

          const createBody = () => {
            const elm = innerDoc.createElement("div");
            elm.appendChild(createTitle());
            elm.appendChild(createDesc());
            elm.style.marginRight = `${imgSize + 10}px`;
            return elm;
          };

          const createFavicon = () => {
            const faviconElm = innerDoc.createElement("img");
            faviconElm.setAttribute("src", ogp.favicon);
            faviconElm.style.width = "18px";
            faviconElm.style.height = "18px";
            faviconElm.style.marginRight = "0.2em";
            faviconElm.style.verticalAlign = "middle";
            return faviconElm;
          };

          const createHostname = () => {
            const hostnameElm = innerDoc.createElement("span");
            hostnameElm.textContent = ogp.hostname;
            hostnameElm.style.fontSize = "12px";
            hostnameElm.style.verticalAlign = "middle";
            hostnameElm.style.overflow = "hidden";
            return hostnameElm;
          };

          const createLeft = () => {
            const leftElm = innerDoc.createElement("div");
            if (ogp.imgSrc) {
              leftElm.appendChild(createImg());
            }
            leftElm.appendChild(createBody());
            leftElm.style.height = `${imgSize}px`;
            leftElm.style.position = "relative";
            return leftElm;
          };

          const createFooter = () => {
            const footerElm = innerDoc.createElement("p");
            if (ogp.favicon) {
              footerElm.appendChild(createFavicon());
            }
            footerElm.appendChild(createHostname());
            footerElm.style.marginTop = "0rem";
            footerElm.style.marginBottom = "0.5rem";
            return footerElm;
          };

          const contentElm = innerDoc.getElementById("content");
          contentElm.appendChild(createLeft());
          contentElm.appendChild(createFooter());
          contentElm.style.backgroundColor = "white";
          contentElm.style.borderRadius = "3px";
          contentElm.style.padding = "0.1rem 1rem";
          contentElm.style.height = `${imgSize + 40}px`;

          const iframeDoc = new jsdom.JSDOM(`
            <iframe
              scrolling="no"
              frameborder="0"
              style="display: block; width: 100%; max-width: 600px; height: ${
                imgSize + 40 + 8 * 2
              }px;"
            >
            </iframe>
          `).window.document;
          iframeDoc.body.firstElementChild.setAttribute(
            "srcdoc",
            innerDoc.documentElement.innerHTML
          );

          return `
            ${iframeDoc.body.innerHTML}
            <!--
          `;
        } else {
          return "-->";
        }
      },
    },
  },
];

hexo.extend.filter.register("markdown-it:renderer", function (md) {
  containers.forEach((c) =>
    md.use(require("markdown-it-container"), c.name, c.options)
  );
});
