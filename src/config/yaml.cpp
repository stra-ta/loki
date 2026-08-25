// Strict YAML-subset parser. Block style only; see AGENTS.md
// "YAML subset accepted by the parser".
#include "yaml_internal.hpp"

#include <cctype>
#include <string>
#include <vector>

namespace loki::cfg {
namespace {

[[noreturn]] void err(const std::string& msg, int line) { throw ScenarioError(msg, line); }

struct Line {
  int no = 0;
  int indent = 0;
  std::string text;  // comment-stripped, right-trimmed content after indent
};

bool is_indent_tab(const std::string& raw, int no) {
  std::size_t i = 0;
  while (i < raw.size() && raw[i] == ' ') ++i;
  if (i < raw.size() && raw[i] == '\t') err("tab used for indentation", no);
  return false;
}

// Strip a '#' comment that is not inside quotes and is preceded by a space or
// starts the content.
std::string strip_comment(const std::string& s, int no) {
  bool in_single = false, in_double = false;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (in_double) {
      if (c == '"') in_double = false;
    } else if (in_single) {
      if (c == '\'') in_single = false;
    } else if (c == '"') {
      in_double = true;
    } else if (c == '\'') {
      in_single = true;
    } else if (c == '#') {
      if (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t') return s.substr(0, i);
    }
  }
  (void)no;
  return s;
}

std::string rtrim(std::string s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.pop_back();
  return s;
}

std::vector<Line> preprocess(const std::string& text) {
  std::vector<Line> lines;
  int no = 0;
  std::size_t pos = 0;
  bool seen_content = false;
  while (pos <= text.size()) {
    auto nl = text.find('\n', pos);
    const std::string raw = rtrim(text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
    ++no;
    is_indent_tab(raw, no);
    std::size_t first = 0;
    while (first < raw.size() && raw[first] == ' ') ++first;
    std::string body = rtrim(strip_comment(raw.substr(first), no));
    const bool blank = body.empty();
    if (!blank) {
      if (body == "---") {
        // A leading document marker is tolerated; any later one means a second
        // document, which the subset rejects.
        if (seen_content || !lines.empty()) err("multiple documents are not allowed", no);
      } else if (body == "...") {
        err("document end marker is not allowed", no);
      } else {
        seen_content = true;
        lines.push_back(Line{no, static_cast<int>(first), body});
      }
    }
    if (nl == std::string::npos) break;
    pos = nl + 1;
  }
  return lines;
}

// Split "key: value" at the first top-level colon followed by space or EOL.
// Returns npos when the text is not a map entry.
std::size_t find_key_colon(const std::string& s) {
  bool in_single = false, in_double = false;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (in_double) {
      if (c == '"') in_double = false;
    } else if (in_single) {
      if (c == '\'') in_single = false;
    } else if (c == '"') {
      in_double = true;
    } else if (c == '\'') {
      in_single = true;
    } else if (c == ':') {
      if (i + 1 == s.size() || s[i + 1] == ' ') return i;
    }
  }
  return std::string::npos;
}

std::string unquote(const std::string& s) {
  if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
    return s.substr(1, s.size() - 2);
  }
  return s;
}

YNode parse_scalar_text(const std::string& raw, int line) {
  YNode n;
  n.line = line;
  std::string s = raw;
  // Trim leading spaces of inline values ("key:   value").
  std::size_t b = 0;
  while (b < s.size() && s[b] == ' ') ++b;
  s = s.substr(b);
  if (s.empty()) err("expected a value", line);
  if (s[0] == '&' || s[0] == '*') err("anchors and aliases are not supported", line);
  if (s[0] == '|' || s[0] == '>') err("block scalars are not supported", line);
  if ((s[0] == '"' || s[0] == '\'')) {
    if (s.size() < 2 || s.back() != s[0]) err("unterminated quoted string", line);
    for (std::size_t i = 1; i + 1 < s.size(); ++i) {
      if (s[i] == s[0]) err("unexpected quote inside quoted scalar", line);
    }
    n.quoted = true;
    n.scalar = s.substr(1, s.size() - 2);
    return n;
  }
  for (const char c : s) {
    if (c == '{' || c == '[' || c == '}' || c == ']') err("flow style is not supported", line);
  }
  n.scalar = s;
  return n;
}

class Parser {
 public:
  explicit Parser(std::vector<Line> lines) : lines_(std::move(lines)) {}

  YNode parse_document() {
    if (lines_.empty()) err("scenario is empty", 1);
    return parse_block(0, lines_[0].indent);
  }

 private:
  bool seq_item(const Line& l) const {
    return l.text == "-" || (l.text.rfind("- ", 0) == 0);
  }

  // Parses the block starting at lines_[i] with exactly `indent` indentation.
  YNode parse_block(std::size_t i, int indent) {
    if (seq_item(lines_[i])) return parse_seq(i, indent);
    return parse_map(i, indent);
  }

  YNode parse_map(std::size_t i, int indent) {
    YNode node;
    node.kind = YNode::Kind::Map;
    node.line = lines_[i].no;
    while (i < lines_.size() && lines_[i].indent >= indent) {
      if (lines_[i].indent > indent) err("bad indentation", lines_[i].no);
      const Line& l = lines_[i];
      const std::size_t colon = find_key_colon(l.text);
      if (colon == std::string::npos) err("expected 'key: value'", l.no);
      std::string key_raw = rtrim(l.text.substr(0, colon));
      if (key_raw.empty()) err("empty mapping key", l.no);
      if (key_raw.find('[') != std::string::npos || key_raw.find('{') != std::string::npos ||
          key_raw.find('*') != std::string::npos || key_raw.find('&') != std::string::npos) {
        err("flow style / anchors / aliases are not supported in keys", l.no);
      }
      const std::string key = unquote(key_raw);
      for (const auto& [k, v] : node.map) {
        (void)v;
        if (k == key) err("duplicate key '" + k + "'", l.no);
      }
      std::string rest = l.text.substr(colon + 1);
      // Inline value?
      std::size_t nb = 0;
      while (nb < rest.size() && rest[nb] == ' ') ++nb;
      if (nb < rest.size()) {
        node.key_lines.push_back(l.no);
        node.map.emplace_back(key, parse_scalar_text(rest, l.no));
        ++i;
        continue;
      }
      // Value on following, more-indented lines.
      ++i;
      if (i >= lines_.size() || lines_[i].indent <= indent) {
        // "key:" with no nested block denotes an empty mapping in this subset
        // (used for zero-field faults such as `reset:`).
        YNode empty;
        empty.kind = YNode::Kind::Map;
        empty.line = l.no;
        node.key_lines.push_back(l.no);
        node.map.emplace_back(key, std::move(empty));
        continue;
      }
      node.key_lines.push_back(l.no);
      node.map.emplace_back(key, parse_block(i, lines_[i].indent));
      // Skip the consumed subtree: parse_block consumed through recursion, but
      // we track position by re-scanning until dedent below.
      while (i < lines_.size() && lines_[i].indent > indent) ++i;
    }
    return node;
  }

  YNode parse_seq(std::size_t i, int indent) {
    YNode node;
    node.kind = YNode::Kind::Seq;
    node.line = lines_[i].no;
    while (i < lines_.size() && lines_[i].indent == indent && seq_item(lines_[i])) {
      const Line l = lines_[i];
      std::string rest = (l.text == "-") ? "" : l.text.substr(2);
      if (rest.empty()) {
        ++i;
        if (i >= lines_.size() || lines_[i].indent <= indent) {
          err("expected an indented block after '-'", l.no);
        }
        node.seq.push_back(parse_block(i, lines_[i].indent));
        while (i < lines_.size() && lines_[i].indent > indent) ++i;
        continue;
      }
      const std::size_t colon = find_key_colon(rest);
      if (colon != std::string::npos) {
        // Inline map start: rewrite this line as a map entry two columns in and
        // parse the map from here so sibling keys align under the item.
        lines_[i].indent = indent + 2;
        lines_[i].text = rest;
        node.seq.push_back(parse_map(i, indent + 2));
        i = skip_to_dedent(i + 1, indent);
        continue;
      }
      node.seq.push_back(parse_scalar_text(rest, l.no));
      ++i;
    }
    return node;
  }

  std::size_t skip_to_dedent(std::size_t i, int indent) {
    while (i < lines_.size() && lines_[i].indent > indent) ++i;
    return i;
  }

  std::vector<Line> lines_;
};

}  // namespace

YNode parse_yaml(const std::string& text) {
  Parser p(preprocess(text));
  return p.parse_document();
}

}  // namespace loki::cfg
