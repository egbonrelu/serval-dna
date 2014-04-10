/*
 MDP packet filtering
 Copyright (C) 2013-2014 Serval Project Inc.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "serval.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "constants.h"
#include "conf.h"
#include "mem.h"

struct packet_rule {
  struct subscriber *source;
  struct subscriber *destination;
  mdp_port_t src_start;
  mdp_port_t src_end;
  mdp_port_t dst_start;
  mdp_port_t dst_end;
  uint8_t flags;
  struct packet_rule *next;
};

static struct packet_rule *packet_rules = NULL;

static int match_rule(struct internal_mdp_header *header, struct packet_rule *rule)
{
  if ((rule->flags & RULE_SOURCE) && header->source != rule->source)
    return 0;
  if ((rule->flags & RULE_DESTINATION) && header->destination != rule->destination)
    return 0;
  if ((rule->flags & RULE_SRC_PORT) && 
      (header->source_port < rule->src_start||header->source_port > rule->src_end))
    return 0;
  if ((rule->flags & RULE_DST_PORT) && 
      (header->destination_port < rule->dst_start||header->destination_port > rule->dst_end))
    return 0;
  if (config.debug.mdprequests)
    DEBUGF("Packet matches %s rule, flags:%s%s%s%s", 
      rule->flags & RULE_DROP ? "DROP" : "ALLOW",
      rule->flags & RULE_SOURCE ? " SOURCE" : "",
      rule->flags & RULE_DESTINATION ? " DESTINATION" : "",
      rule->flags & RULE_SRC_PORT? " SOURCE_PORT" : "",
      rule->flags & RULE_DST_PORT ? " DESTINATION_PORT" : "");
  return 1;
}

int allow_incoming_packet(struct internal_mdp_header *header)
{
  struct packet_rule *rule;
  for (rule = packet_rules; rule; rule = rule->next)
    if (match_rule(header, rule))
      return rule->flags & RULE_DROP;
  return RULE_ALLOW;
}

static void free_rule_list(struct packet_rule *rule)
{
  while(rule){
    struct packet_rule *t = rule;
    rule = rule->next;
    free(t);
  }
}

/*
 * rules := optspace rule optspace ( sep optspace rule optspace ){0..}
 * sep := "\n" | ";"
 * rule := verb space pattern
 * verb := "allow" | "drop"
 * pattern := "all" | srcpat optspace [ dstpat ] | dstpat optspace [ srcpat ]
 * srcpat := "<" optspace endpoint
 * dstpat := ">" optspace endpoint
 * endpoint := [ sid ] [ optspace ":" optspace portrange ]
 * sid := sidhex | "broadcast"
 * sidhex := hexdigit {64}
 * portrange := port [ optspace "-" optspace port ]
 * port := hexport | decport
 * hexport := "0x" hexdigit {1..8}
 * decport := decdigit {1..10}
 * decdigit := "0".."9"
 * hexdigit := decdigit | "A".."F" | "a".."f"
 * optspace := " " {0..}
 * space := " " {1..}
 */

static int _space(const char **cursor)
{
  if (**cursor != ' ')
    return 0;
  while (**cursor == ' ')
    ++*cursor;
  return 1;
}

static int _optspace(const char **cursor)
{
  _space(cursor);
  return 1;
}

static int _sep(const char **cursor)
{
  if (**cursor == '\n' || **cursor == ';') {
    ++*cursor;
    return 1;
  }
  return 0;
}

static int _port(const char **cursor, mdp_port_t *portp)
{
  const char *end;
  if (!(((*cursor)[0] == '0' && (*cursor)[1] == 'x') ? str_to_uint32(*cursor + 2, 16, portp, &end) : str_to_uint32(*cursor, 10, portp, &end)))
    return 0;
  *cursor = end;
  return 1;
}

static int _portrange(const char **cursor, mdp_port_t *port_start, mdp_port_t *port_end)
{
  if (!_port(cursor, port_start))
    return 0;
  const char *end = *cursor;
  _optspace(cursor);
  if (**cursor == '-') {
    ++*cursor;
    _optspace(cursor);
    if (!_port(cursor, port_end))
      return 0;
  } else {
    *cursor = end;
    *port_end = *port_start;
  }
  return 1;

}

static int _endpoint(const char **cursor, uint8_t *flagsp, uint8_t sid_flag, uint8_t port_flag, struct subscriber **subscr, mdp_port_t *port_start, mdp_port_t *port_end)
{
  const char *end;
  sid_t sid;
  if (strn_to_sid_t(&sid, *cursor, &end) == 0) {
    if ((*subscr = find_subscriber(sid.binary, sizeof sid.binary, 1)) == NULL)
      return 0;
    *flagsp |= sid_flag;
    *cursor = end;
  } else if (end != *cursor)
    return 0;
  _optspace(cursor);
  if (**cursor == ':') {
    ++*cursor;
    _optspace(cursor);
    if (!_portrange(cursor, port_start, port_end))
      return 0;
    *flagsp |= port_flag;
  } else
    *cursor = end;
  return 1;
}

static int _srcpat(const char **cursor, struct packet_rule *rule)
{
  if (**cursor != '<')
    return 0;
  ++*cursor;
  _optspace(cursor);
  return _endpoint(cursor, &rule->flags, RULE_SOURCE, RULE_SRC_PORT, &rule->source, &rule->src_start, &rule->src_end);
}

static int _dstpat(const char **cursor, struct packet_rule *rule)
{
  if (**cursor != '>')
    return 0;
  ++*cursor;
  _optspace(cursor);
  return _endpoint(cursor, &rule->flags, RULE_DESTINATION, RULE_DST_PORT, &rule->destination, &rule->dst_start, &rule->dst_end);
}

static int _pattern(const char **cursor, struct packet_rule *rule)
{
  if (strcmp(*cursor, "all") == 0)
    return 1;
  if (**cursor == '<')
    return _srcpat(cursor, rule) && _optspace(cursor) && (**cursor == '>' ? _dstpat(cursor, rule) : 1);
  if (**cursor == '>')
    return _dstpat(cursor, rule) && _optspace(cursor) && (**cursor == '<' ? _srcpat(cursor, rule) : 1);
  return 0;
}

static int _verb(const char **cursor, struct packet_rule *rule)
{
  if (strcmp(*cursor, "allow") == 0)
    return 1;
  if (strcmp(*cursor, "drop") == 0) {
    rule->flags |= RULE_DROP;
    return 1;
  }
  return 0;
}

static int _rule(const char **cursor, struct packet_rule **rulep)
{
  assert(*rulep == NULL);
  if ((*rulep = emalloc_zero(sizeof(struct packet_rule))) == NULL)
    return -1;
  if (_verb(cursor, *rulep) && _optspace(cursor) && _pattern(cursor, *rulep))
    return 1;
  free(*rulep);
  *rulep = NULL;
  return 0;
}

static int _rules(const char **cursor, struct packet_rule **listp)
{
  assert(*listp == NULL);
  _optspace(cursor);
  int r;
  if ((r = _rule(cursor, listp)) == -1)
    return -1;
  if (!r)
    return 0;
  assert(*listp != NULL);
  listp = &(*listp)->next;
  assert(*listp == NULL);
  _optspace(cursor);
  while (**cursor && _sep(cursor) && **cursor) {
    _optspace(cursor);
    if ((r = _rule(cursor, listp)) == -1)
      return -1;
    if (!r)
      return 0;
    assert(*listp != NULL);
    listp = &(*listp)->next;
    assert(*listp == NULL);
    _optspace(cursor);
  }
  return **cursor == '\0';
}

/* Parse the given text as a list of MDP filter rules and return the pointer to the head of the list
 * if successful.  List elements are allocated using malloc(3).  The 'source' and 'destination'
 * subscriber structs are allocated using find_subscriber() for each SID parsed in the rules.  Does
 * not alter the rules currently in force -- use set_mdp_packet_rules() for that.
 *
 * Returns NULL if the parsing fails because of either a malformed text or system failure (out of
 * memory).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct packet_rule *parse_mdp_packet_rules(const char *text)
{
  struct packet_rule *rules = NULL;
  int r;
  if ((r = _rules(&text, &rules)) == 1)
    return rules;
  if (r == -1)
    WHY("failure parsing packet filter rules");
  else
    WHYF("malformed packet filter rule at %s", alloca_toprint(30, text, strlen(text)));
  free_rule_list(rules);
  return NULL;
}

/* Replace the current packet filter rules with the given new list of rules.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void set_mdp_packet_rules(struct packet_rule *rules)
{
  clear_mdp_packet_rules();
  packet_rules = rules;
}

/* Clear the current packet filter rules, leaving no rules in force.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void clear_mdp_packet_rules()
{
  free_rule_list(packet_rules);
  packet_rules = NULL;
}

/* (Re-)load the packet filter rules from the configured file.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void reload_mdp_packet_rules()
{
  char rules_path[1024];
  if (FORMF_SERVAL_ETC_PATH(rules_path, "%s", config.mdp.filter_rules_path)) {
    unsigned char *buf = NULL;
    size_t size = 16 * 1024; // maximum file size
    if (malloc_read_whole_file(rules_path, &buf, &size) == -1)
      WHYF("failed to read rules file %s", alloca_str_toprint(rules_path));
    else {
      assert(buf != NULL);
      struct packet_rule *new_rules = parse_mdp_packet_rules((char *)buf, size);
      if (new_rules)
	set_mdp_packet_rules(new_rules);
    }
  }
}
