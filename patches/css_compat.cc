// GoldenBoot: CSS compatibility rewrites for Cobalt. See css_compat.h.

#include "cobalt/css_parser/css_compat.h"

#include <stddef.h>

#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace cobalt {
namespace css_parser {
namespace css_compat {

namespace {

typedef std::map<std::string, std::string> VarMap;

std::once_flag g_once;
std::mutex* g_mutex = nullptr;  // heap: no exit-time destructor
VarMap* g_vars = nullptr;

void Init() {
  std::call_once(g_once, [] {
    g_mutex = new std::mutex();
    g_vars = new VarMap();
  });
}

bool IsIdent(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '-' || c == '_' || static_cast<unsigned char>(c) >= 0x80;
}

bool IsSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

std::string Trim(const std::string& s) {
  size_t b = 0;
  size_t e = s.size();
  while (b < e && IsSpace(s[b])) ++b;
  while (e > b && IsSpace(s[e - 1])) --e;
  return s.substr(b, e - b);
}

// Index after a quoted string starting at i (s[i] is the quote).
size_t SkipString(const std::string& s, size_t i) {
  char q = s[i++];
  while (i < s.size() && s[i] != q) {
    if (s[i] == '\\') ++i;
    ++i;
  }
  return i < s.size() ? i + 1 : s.size();
}

// End of a declaration value starting at i: the next ';' or '}' outside
// brackets and strings (or the end of s).
size_t ValueEnd(const std::string& s, size_t i) {
  int depth = 0;
  while (i < s.size()) {
    char c = s[i];
    if (c == '"' || c == '\'') {
      i = SkipString(s, i);
      continue;
    }
    if (c == '(' || c == '[') ++depth;
    if ((c == ')' || c == ']') && depth > 0) --depth;
    if (depth == 0 && (c == ';' || c == '}')) return i;
    ++i;
  }
  return i;
}

// Index of the ')' closing the '(' at s[open], or npos.
size_t CloseParen(const std::string& s, size_t open) {
  int depth = 0;
  size_t i = open;
  while (i < s.size()) {
    char c = s[i];
    if (c == '"' || c == '\'') {
      i = SkipString(s, i);
      continue;
    }
    if (c == '(') ++depth;
    if (c == ')' && --depth == 0) return i;
    ++i;
  }
  return std::string::npos;
}

// Splits s at top-level commas.
std::vector<std::string> SplitArgs(const std::string& s) {
  std::vector<std::string> out;
  int depth = 0;
  size_t start = 0;
  size_t i = 0;
  while (i < s.size()) {
    char c = s[i];
    if (c == '"' || c == '\'') {
      i = SkipString(s, i);
      continue;
    }
    if (c == '(') ++depth;
    if (c == ')' && depth > 0) --depth;
    if (c == ',' && depth == 0) {
      out.push_back(Trim(s.substr(start, i - start)));
      start = i + 1;
    }
    ++i;
  }
  out.push_back(Trim(s.substr(start)));
  return out;
}

// Collects "--name: value" declarations (first one in this text wins).
void CollectVars(const std::string& s, VarMap* vars) {
  bool decl_start = true;
  size_t i = 0;
  const size_t n = s.size();
  while (i < n) {
    char c = s[i];
    if (c == '/' && i + 1 < n && s[i + 1] == '*') {
      size_t e = s.find("*/", i + 2);
      i = e == std::string::npos ? n : e + 2;
      continue;
    }
    if (c == '"' || c == '\'') {
      i = SkipString(s, i);
      decl_start = false;
      continue;
    }
    if (c == '{' || c == ';' || c == '}') {
      decl_start = true;
      ++i;
      continue;
    }
    if (IsSpace(c)) {
      ++i;
      continue;
    }
    if (decl_start && c == '-' && i + 2 < n && s[i + 1] == '-' && IsIdent(s[i + 2])) {
      size_t j = i + 2;
      while (j < n && IsIdent(s[j])) ++j;
      size_t k = j;
      while (k < n && IsSpace(s[k])) ++k;
      if (k < n && s[k] == ':') {
        size_t e = ValueEnd(s, k + 1);
        std::string value = Trim(s.substr(k + 1, e - k - 1));
        size_t imp = value.find("!important");
        if (imp != std::string::npos) value = Trim(value.substr(0, imp));
        std::string name = s.substr(i, j - i);
        if (!vars->count(name)) (*vars)[name] = value;
        i = e;
        decl_start = false;
        continue;
      }
    }
    decl_start = false;
    ++i;
  }
}

// Replaces clamp()/min()/max() and resolves var() in s.
std::string Rewrite(const std::string& s, const VarMap& vars, int depth) {
  if (depth > 8) return s;
  std::string out;
  out.reserve(s.size());
  size_t i = 0;
  const size_t n = s.size();
  while (i < n) {
    char c = s[i];
    if (c == '"' || c == '\'') {
      size_t e = SkipString(s, i);
      out.append(s, i, e - i);
      i = e;
      continue;
    }
    if (c == '/' && i + 1 < n && s[i + 1] == '*') {
      size_t e = s.find("*/", i + 2);
      e = e == std::string::npos ? n : e + 2;
      out.append(s, i, e - i);
      i = e;
      continue;
    }
    bool boundary = i == 0 || !IsIdent(s[i - 1]);
    const char* fn = nullptr;
    size_t fn_len = 0;
    if (boundary) {
      if (s.compare(i, 4, "var(") == 0) {
        fn = "var";
        fn_len = 3;
      } else if (s.compare(i, 6, "clamp(") == 0) {
        fn = "clamp";
        fn_len = 5;
      } else if (s.compare(i, 4, "min(") == 0) {
        fn = "min";
        fn_len = 3;
      } else if (s.compare(i, 4, "max(") == 0) {
        fn = "max";
        fn_len = 3;
      }
    }
    if (!fn) {
      out.push_back(c);
      ++i;
      continue;
    }
    size_t open = i + fn_len;
    size_t close = CloseParen(s, open);
    if (close == std::string::npos) {
      out.append(s, i, n - i);
      break;
    }
    std::string inner = s.substr(open + 1, close - open - 1);
    std::vector<std::string> args = SplitArgs(inner);
    std::string repl;
    bool ok = true;
    if (fn[0] == 'v') {
      std::string name = args[0];
      auto it = vars.find(name);
      if (it != vars.end()) {
        repl = Rewrite(it->second, vars, depth + 1);
      } else if (args.size() > 1) {
        // fallback: everything after the first comma
        size_t comma = inner.find(',');
        repl = Rewrite(Trim(inner.substr(comma + 1)), vars, depth + 1);
      } else {
        ok = false;
      }
    } else if (fn[0] == 'c') {
      if (args.size() == 3) {
        repl = Rewrite(args[1], vars, depth + 1);
      } else {
        ok = false;
      }
    } else if (fn[1] == 'i') {  // min
      repl = Rewrite(args.front(), vars, depth + 1);
    } else {  // max
      repl = Rewrite(args.back(), vars, depth + 1);
    }
    if (ok) {
      out += repl;
    } else {
      out.append(s, i, close + 1 - i);
    }
    i = close + 1;
  }
  return out;
}

// Expands "inset: a b c d" into top/right/bottom/left.
std::string ExpandInset(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  bool decl_start = true;
  size_t i = 0;
  const size_t n = s.size();
  while (i < n) {
    char c = s[i];
    if (c == '/' && i + 1 < n && s[i + 1] == '*') {
      size_t e = s.find("*/", i + 2);
      e = e == std::string::npos ? n : e + 2;
      out.append(s, i, e - i);
      i = e;
      continue;
    }
    if (c == '"' || c == '\'') {
      size_t e = SkipString(s, i);
      out.append(s, i, e - i);
      i = e;
      decl_start = false;
      continue;
    }
    if (c == '{' || c == ';' || c == '}') {
      decl_start = true;
      out.push_back(c);
      ++i;
      continue;
    }
    if (IsSpace(c)) {
      out.push_back(c);
      ++i;
      continue;
    }
    if (decl_start && s.compare(i, 5, "inset") == 0 && (i + 5 >= n || !IsIdent(s[i + 5]))) {
      size_t k = i + 5;
      while (k < n && IsSpace(s[k])) ++k;
      if (k < n && s[k] == ':') {
        size_t e = ValueEnd(s, k + 1);
        std::string value = Trim(s.substr(k + 1, e - k - 1));
        std::string imp;
        size_t ip = value.find("!important");
        if (ip != std::string::npos) {
          imp = " !important";
          value = Trim(value.substr(0, ip));
        }
        std::vector<std::string> v;
        int depth = 0;
        size_t st = 0;
        for (size_t j = 0; j <= value.size(); ++j) {
          char d = j < value.size() ? value[j] : ' ';
          if (d == '(') ++depth;
          if (d == ')' && depth > 0) --depth;
          if (IsSpace(d) && depth == 0) {
            if (j > st) v.push_back(value.substr(st, j - st));
            st = j + 1;
          }
        }
        if (!v.empty() && v.size() <= 4) {
          std::string t = v[0];
          std::string r = v.size() > 1 ? v[1] : t;
          std::string b = v.size() > 2 ? v[2] : t;
          std::string l = v.size() > 3 ? v[3] : r;
          out += "top:" + t + imp + ";right:" + r + imp + ";bottom:" + b + imp + ";left:" + l + imp;
          i = e;
          decl_start = false;
          continue;
        }
      }
    }
    decl_start = false;
    out.push_back(c);
    ++i;
  }
  return out;
}

bool Has(const std::string& s, const char* what) {
  return s.find(what) != std::string::npos;
}

}  // namespace

const std::string& Process(const std::string& input, std::string* storage) {
  const bool vars = Has(input, "var(");
  const bool defs = Has(input, "--");
  const bool math = Has(input, "clamp(") || Has(input, "min(") || Has(input, "max(");
  const bool inset = Has(input, "inset");
  if (!vars && !defs && !math && !inset) return input;
  Init();
  VarMap snapshot;
  {
    std::lock_guard<std::mutex> lock(*g_mutex);
    if (defs) {
      VarMap local;
      CollectVars(input, &local);
      for (const auto& kv : local) (*g_vars)[kv.first] = kv.second;
    }
    if (vars) snapshot = *g_vars;
  }
  if (!vars && !math && !inset) return input;
  std::string text = (vars || math) ? Rewrite(input, snapshot, 0) : input;
  if (inset) text = ExpandInset(text);
  if (text == input) return input;
  *storage = std::move(text);
  return *storage;
}

}  // namespace css_compat
}  // namespace css_parser
}  // namespace cobalt
