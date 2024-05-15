/**
 * Very simple basic rule set
 *
 * Allows
 *    <i>, <em>, <b>, <strong>, <p>, <div>, <a href="http://foo"></a>, <br>, <span>, <ol>, <ul>, <li>
 *
 * For a proper documentation of the format check advanced.js
 */
var wysihtml5ParserRules = {
  "type_definitions": {
      "text_bg_color_object": {
        "styles": {
          "background-color": true
        }
      },
  },
  tags: {
    strong: {},
    b:      {},
    i:      {},
    em:     {},
    u:     {},
    s:     {},
    del:     {},
    br:     {},
    p:      {},
    div:    {},
   "span": {
        "one_of_type": {
            "text_bg_color_object": 1
        },
        "keep_styles": {
            "backgroundColor": 1
        },
        "remove_action": "unwrap"
    },
    blockquote: {},

      ul:     {},
    ol:     {},
    li:     {},
      h1: {},
      h2: {},
      h3: {},
      h4: {},
      h5: {},
      h6: {},
      pre: {},
      code: {},
      tt: {},
      dd: {},
      dt: {},
    table: {},
      thead: {},
      tbody:{},
      tr:{},
      th:{},

    "td": {
        "check_attributes": {
            "rowspan": "numbers",
            "colspan": "numbers"
        }
    },
    "img": {
        "check_attributes": {
            "width": "numbers",
            "alt": "alt",
            "src": "any",
            "height": "numbers"
        }
    },
    a:      {
      set_attributes: {
        target: "_blank",
        rel:    "nofollow"
      },
      check_attributes: {
        href:   "url" // important to avoid XSS
      }
    }
  }
};
