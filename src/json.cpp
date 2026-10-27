// Claude-Rays Decompiler - minimal JSON support
#include "json.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace clauderays
{

//------------------------------------------------------------------------------
const json_t *json_t::get(const char *key) const
{
  if ( type != JOBJECT )
    return nullptr;
  for ( const auto &kv : obj )
    if ( kv.first == key )
      return &kv.second;
  return nullptr;
}

//------------------------------------------------------------------------------
std::string json_t::str(const char *key) const
{
  const json_t *v = get(key);
  if ( v == nullptr || v->type == JNULL )
    return std::string();
  return v->as_text();
}

//------------------------------------------------------------------------------
std::string json_t::as_text() const
{
  return type == JSTR ? s : dump();
}

//------------------------------------------------------------------------------
std::string json_quote(const std::string &s)
{
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for ( unsigned char c : s )
  {
    switch ( c )
    {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if ( c < 0x20 )
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        }
        else
        {
          out += char(c);   // UTF-8 bytes are passed as is
        }
        break;
    }
  }
  out += '"';
  return out;
}

//------------------------------------------------------------------------------
std::string json_t::dump() const
{
  switch ( type )
  {
    case JNULL: return "null";
    case JBOOL: return b ? "true" : "false";
    case JNUM:  return s.empty() ? std::to_string(num) : s;
    case JSTR:  return json_quote(s);
    case JARRAY:
      {
        std::string out = "[";
        for ( size_t i = 0; i < arr.size(); i++ )
        {
          if ( i != 0 )
            out += ", ";
          out += arr[i].dump();
        }
        return out + "]";
      }
    case JOBJECT:
      {
        std::string out = "{";
        for ( size_t i = 0; i < obj.size(); i++ )
        {
          if ( i != 0 )
            out += ", ";
          out += json_quote(obj[i].first);
          out += ": ";
          out += obj[i].second.dump();
        }
        return out + "}";
      }
  }
  return "null";
}

//------------------------------------------------------------------------------
// parser
//------------------------------------------------------------------------------
struct json_parser_t
{
  const std::string &t;
  size_t p = 0;
  std::string err;

  explicit json_parser_t(const std::string &text) : t(text) {}

  bool fail(const char *what)
  {
    if ( err.empty() )
    {
      char buf[128];
      snprintf(buf, sizeof(buf), "%s at offset %u", what, unsigned(p));
      err = buf;
    }
    return false;
  }

  void ws()
  {
    while ( p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r') )
      p++;
  }

  bool lit(const char *w)
  {
    size_t n = strlen(w);
    if ( t.compare(p, n, w) != 0 )
      return false;
    p += n;
    return true;
  }

  static void put_utf8(std::string *out, uint32_t cp)
  {
    if ( cp < 0x80 )
    {
      *out += char(cp);
    }
    else if ( cp < 0x800 )
    {
      *out += char(0xC0 | (cp >> 6));
      *out += char(0x80 | (cp & 0x3F));
    }
    else if ( cp < 0x10000 )
    {
      *out += char(0xE0 | (cp >> 12));
      *out += char(0x80 | ((cp >> 6) & 0x3F));
      *out += char(0x80 | (cp & 0x3F));
    }
    else
    {
      *out += char(0xF0 | (cp >> 18));
      *out += char(0x80 | ((cp >> 12) & 0x3F));
      *out += char(0x80 | ((cp >> 6) & 0x3F));
      *out += char(0x80 | (cp & 0x3F));
    }
  }

  bool hex4(uint32_t *out)
  {
    if ( p + 4 > t.size() )
      return fail("truncated \\u escape");
    uint32_t v = 0;
    for ( int i = 0; i < 4; i++ )
    {
      char c = t[p++];
      v <<= 4;
      if ( c >= '0' && c <= '9' )      v |= c - '0';
      else if ( c >= 'a' && c <= 'f' ) v |= c - 'a' + 10;
      else if ( c >= 'A' && c <= 'F' ) v |= c - 'A' + 10;
      else return fail("bad \\u escape");
    }
    *out = v;
    return true;
  }

  bool string(std::string *out)
  {
    if ( p >= t.size() || t[p] != '"' )
      return fail("expected string");
    p++;
    while ( p < t.size() )
    {
      char c = t[p++];
      if ( c == '"' )
        return true;
      if ( c != '\\' )
      {
        *out += c;
        continue;
      }
      if ( p >= t.size() )
        break;
      char e = t[p++];
      switch ( e )
      {
        case '"':  *out += '"'; break;
        case '\\': *out += '\\'; break;
        case '/':  *out += '/'; break;
        case 'b':  *out += '\b'; break;
        case 'f':  *out += '\f'; break;
        case 'n':  *out += '\n'; break;
        case 'r':  *out += '\r'; break;
        case 't':  *out += '\t'; break;
        case 'u':
          {
            uint32_t cp;
            if ( !hex4(&cp) )
              return false;
            if ( cp >= 0xD800 && cp <= 0xDBFF
              && p + 6 <= t.size() && t[p] == '\\' && t[p + 1] == 'u' )
            {
              size_t save = p;
              p += 2;
              uint32_t lo;
              if ( hex4(&lo) && lo >= 0xDC00 && lo <= 0xDFFF )
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              else
                p = save, err.clear();
            }
            put_utf8(out, cp);
          }
          break;
        default:
          return fail("bad escape");
      }
    }
    return fail("unterminated string");
  }

  bool number(json_t *out)
  {
    size_t start = p;
    if ( p < t.size() && (t[p] == '-' || t[p] == '+') )
      p++;
    while ( p < t.size() && (isdigit((unsigned char)t[p]) || t[p] == '.' || t[p] == 'e' || t[p] == 'E' || t[p] == '-' || t[p] == '+') )
      p++;
    if ( p == start )
      return fail("unexpected character");
    out->type = json_t::JNUM;
    out->s = t.substr(start, p - start);
    out->num = strtod(out->s.c_str(), nullptr);
    return true;
  }

  bool value(json_t *out, int depth)
  {
    if ( depth > 200 )
      return fail("nesting too deep");
    ws();
    if ( p >= t.size() )
      return fail("unexpected end of input");
    char c = t[p];
    if ( c == '"' )
    {
      out->type = json_t::JSTR;
      return string(&out->s);
    }
    if ( c == '{' )
    {
      p++;
      out->type = json_t::JOBJECT;
      ws();
      if ( p < t.size() && t[p] == '}' )
      {
        p++;
        return true;
      }
      for ( ;; )
      {
        ws();
        std::string key;
        if ( !string(&key) )
          return false;
        ws();
        if ( p >= t.size() || t[p] != ':' )
          return fail("expected ':'");
        p++;
        json_t v;
        if ( !value(&v, depth + 1) )
          return false;
        out->obj.emplace_back(std::move(key), std::move(v));
        ws();
        if ( p < t.size() && t[p] == ',' )
        {
          p++;
          continue;
        }
        if ( p < t.size() && t[p] == '}' )
        {
          p++;
          return true;
        }
        return fail("expected ',' or '}'");
      }
    }
    if ( c == '[' )
    {
      p++;
      out->type = json_t::JARRAY;
      ws();
      if ( p < t.size() && t[p] == ']' )
      {
        p++;
        return true;
      }
      for ( ;; )
      {
        json_t v;
        if ( !value(&v, depth + 1) )
          return false;
        out->arr.push_back(std::move(v));
        ws();
        if ( p < t.size() && t[p] == ',' )
        {
          p++;
          continue;
        }
        if ( p < t.size() && t[p] == ']' )
        {
          p++;
          return true;
        }
        return fail("expected ',' or ']'");
      }
    }
    if ( lit("true") )  { out->type = json_t::JBOOL; out->b = true;  return true; }
    if ( lit("false") ) { out->type = json_t::JBOOL; out->b = false; return true; }
    if ( lit("null") )  { out->type = json_t::JNULL; return true; }
    return number(out);
  }
};

//------------------------------------------------------------------------------
bool json_parse(const std::string &text, json_t *out, std::string *err)
{
  json_parser_t jp(text);
  *out = json_t();
  bool ok = jp.value(out, 0);
  if ( ok )
  {
    jp.ws();
    if ( jp.p != text.size() )
      ok = jp.fail("trailing data");
  }
  if ( !ok && err != nullptr )
    *err = jp.err;
  return ok;
}

} // namespace clauderays
