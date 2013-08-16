#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "print.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* strnchr(const char *str, size_t len, int character) {
  const char* end = str + len;
  char c = (char) character;

  do {
    if (*str == c) {
      return str;
    }
  } while (++str < end);

  return NULL;
}

void printIndent(int indent) {
  for (int index = 0; index < indent; index++) {
    printf(" ");
  }
}

void printIndented(int indent, const char* str, int len) {
  const char* tmp = str;

  while (len > 0) {
    const char* rPos = strnchr(tmp, len, '\r');
    const char* nPos = strnchr(tmp, len, '\n');
    printIndent(indent);

    if (nPos != NULL && (nPos - tmp) < len) {
      if (rPos != NULL && rPos < nPos) {
	PRINT_BUFFER(tmp, rPos - tmp);
      } else {
	PRINT_BUFFER(tmp, nPos - tmp);
      }

      len -= nPos - tmp + 1;
      tmp = nPos + 1;
    } else {
      PRINT_BUFFER(tmp, len);
      len = 0;
    }

    printf("\n");
  }
}

#ifdef ENABLE_JSON

void printJsonArrayContent(JsonArray*, guint, JsonNode*, gpointer);
void printJsonObject(JsonObject*, unsigned int* indent);

void printJsonNode(JsonNode* node, unsigned int* indent) {
  JsonArray* array;
  JsonObject* obj;

  switch (json_node_get_node_type(node)) {
  case JSON_NODE_OBJECT:
    obj = json_node_get_object(node);
    printf("{\n");
    *indent += 2;
    printJsonObject(obj, indent);
    *indent -= 2;
    printIndent(*indent);
    printf("}");
    break;

  case JSON_NODE_ARRAY:
    array = json_node_get_array(node);
    printf("[\n");
    *indent += 2;
    json_array_foreach_element(array, printJsonArrayContent, indent);
    *indent -= 2;
    printIndent(*indent);
    printf("]");
    break;

  case JSON_NODE_VALUE:
    switch (json_node_get_value_type(node)) {
    case G_TYPE_STRING:
      printf("\"%s\"", json_node_get_string(node));
      break;

    case G_TYPE_BOOLEAN:
      printf("%s", json_node_get_boolean(node) ? "true" : "false");
      break;

    case G_TYPE_DOUBLE:
      printf("%f", json_node_get_double(node));
      break;

    case G_TYPE_INT64:
      printf("%lld", (long long) json_node_get_int(node));
      break;

    default:
      printf("unknown_value_type");
      break;
    }
    break;

  case JSON_NODE_NULL:
    printf("null");
    break;
  }
}

void printJsonArrayContent(JsonArray* array, guint index, JsonNode* array_node, gpointer data) {
  unsigned int* indent = (unsigned int*) data;
  printIndent(*indent);
  printJsonNode(array_node, indent);

  if (index < json_array_get_length(array) - 1) {
    printf(",");
  }

  printf("\n");
}

void printJsonObject(JsonObject* object, unsigned int* indent) {
  GList* element;
  GList* members = json_object_get_members(object);

  for (element = members; element; element = element->next) {
    JsonNode* node = json_object_get_member(object, (const gchar*) element->data);

    printIndent(*indent);
    printf("\"%s\":", (const gchar*) element->data);
    printJsonNode(node, indent);

    if (element->next != NULL) {
      printf(",");
    }

    printf("\n");
  }

  g_list_free(members);
}

void printJson(JsonObject* obj) {
  unsigned int indent = 6;
  printIndent(4);
  printf("{\n");
  printJsonObject(obj, &indent);
  printIndent(4);
  printf("}\n");
}

#endif /* ENABLE_JSON */
