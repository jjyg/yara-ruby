/*
 *  yara-ruby - Ruby bindings for the yara malware analysis library.
 *  Eric Monti
 *  Copyright (C) 2011 Trustwave Holdings
 *  
 *  This program is free software: you can redistribute it and/or modify it 
 *  under the terms of the GNU General Public License as published by the 
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *  
 *  You should have received a copy of the GNU General Public License along
 *  with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
*/

#include "Match.h"
#include "Yara_native.h"
#include <stdio.h>

VALUE class_Rules = Qnil;

void rules_mark(YR_COMPILER *ctx) { }

void rules_free(YR_COMPILER *ctx) {
  yr_compiler_destroy(ctx);
}

VALUE rules_allocate(VALUE klass) {
  YR_COMPILER *ctx = NULL;
  if (yr_compiler_create(&ctx) != ERROR_SUCCESS)
    rb_raise(rb_eNoMemError, "Cannot allocate memory");

  return Data_Wrap_Struct(klass, rules_mark, rules_free, ctx);
}

/* 
 * call-seq:
 *      rules.compile_file(filename, ns=nil) -> nil
 *
 * Compiles rules taken from a file by its filename. This method
 * can be called more than once using multiple rules strings and
 * can be used in combination with compile_file.
 *
 * To avoid namespace conflicts, you can use set_namespace
 * before compiling rules.
 *
 * @param [String]     filename  The name of a yara rules file to compile.
 *
 * @param [String,nil] ns        Optional namespace for the rules.
 *
 * @raise [Yara::CompileError] An exception is raised if a compile error occurs.
 */
VALUE rules_compile_file(int argc, VALUE *argv, VALUE self) {
  FILE *file;
  char *fname, *ns = NULL;
  YR_COMPILER *ctx;
  char error_message[256];

  VALUE rb_fname;
  VALUE rb_ns;

  rb_scan_args(argc, argv, "11", &rb_fname, &rb_ns);

  Check_Type(rb_fname, T_STRING);

  if (rb_ns != Qnil) {
    Check_Type(rb_ns, T_STRING);
    ns = RSTRING_PTR(rb_ns);
  }

  fname = RSTRING_PTR(rb_fname);
  if ( !(file=fopen(fname, "r")) ) {
    rb_raise(error_CompileError, "No such file: %s", fname);
  } else {
    Data_Get_Struct(self, YR_COMPILER, ctx);

    yr_compiler_push_file_name(ctx, fname);
    int err = yr_compiler_add_file(ctx, file, ns);
    fclose(file);

    if (err) {
      yr_compiler_get_error_message(ctx, error_message, sizeof(error_message));
      rb_raise(error_CompileError, "Syntax Error - %s(%d): %s", fname, ctx->last_error_line, error_message);
    }

    return Qtrue;
  }

  return Qfalse;
}

/* 
 * call-seq:
 *      rules.compile_string(rules_string, ns=nil) -> nil
 *
 * Compiles rules taken from a ruby string. This method
 * can be called more than once using multiple rules strings
 * and can be used in combination with compile_file.
 *
 * To avoid namespace conflicts, you can set a namespace using
 * the optional 'ns' argument.
 *
 * @param [String] rules_string   A string containing yara rules text.
 *
 * @param [String,nil] ns         An optional namespace for the rules.
 *
 * @raise [Yara::CompileError] An exception is raised if a compile error occurs.
 */
VALUE rules_compile_string(int argc, VALUE *argv, VALUE self) {
  YR_COMPILER *ctx;
  char *rules, *ns = NULL;
  char error_message[256];

  VALUE rb_rules;
  VALUE rb_ns;

  rb_scan_args(argc, argv, "11", &rb_rules, &rb_ns);

  Check_Type(rb_rules, T_STRING);
  if (rb_ns != Qnil) {
    Check_Type(rb_ns, T_STRING);
    ns = RSTRING_PTR(rb_ns);
  }

  rules = RSTRING_PTR(rb_rules);
  Data_Get_Struct(self, YR_COMPILER, ctx);

  if (yr_compiler_add_string(ctx, rules, ns) != 0) {
      yr_compiler_get_error_message(ctx, error_message, sizeof(error_message));
      rb_raise(error_CompileError, "Syntax Error - line(%d): %s", ctx->last_error_line, error_message);
  }

  return Qtrue;
}

/* 
 * call-seq:
 *      rules.current_namespace() -> String
 *
 * @return String Returns the name of the currently active namespace.
 *
 * XXX seems to point to corrupted memory after scan_file...
 */
VALUE rules_current_namespace(VALUE self) {
  YR_COMPILER *ctx;
  Data_Get_Struct(self, YR_COMPILER, ctx);
  if (ctx->current_namespace && ctx->current_namespace->name)
    return rb_str_new2(ctx->current_namespace->name);
  else
    return rb_str_new2("default");
}

/* an internal callback function used with scan_file and scan_string */
static int 
scan_callback(int message, YR_RULE *rule, void *data) {
  int match_ret = CALLBACK_CONTINUE;
  VALUE match = Qnil;
  VALUE results = *((VALUE *) data);

  if (message == CALLBACK_MSG_RULE_MATCHING) {
    Check_Type(results, T_ARRAY);

    match_ret = Match_NEW_from_rule(rule, &match);
    if (match_ret == 0 && !NIL_P(match))
      rb_ary_push(results, match);
  }

  return match_ret;
}

/* 
 * call-seq:
 *      rules.scan_file(filename) -> Array
 *
 * Scans a file using the compiled rules supplied
 * with either compile_file or compile_string (or both).
 *
 * @param [String] filename The name of a file to scan with yara.
 *
 * @return [Yara::Match] An array of Yara::Match objects found in the file.
 *
 * @raise [Yara::ScanError] Raised if an error occurs while scanning the file.
 */
VALUE rules_scan_file(VALUE self, VALUE rb_fname) {
  YR_COMPILER *ctx;
  VALUE results;
  unsigned int ret;
  char *fname;

  Check_Type(rb_fname, T_STRING);
  results = rb_ary_new();
  Data_Get_Struct(self, YR_COMPILER, ctx);
  fname = RSTRING_PTR(rb_fname);

  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(ctx, &rules))
    rb_raise(error_ScanError, "Error retrieving rules"); 

  int fast_mode = 0;	// TODO
  int timeout = 0;	// TODO
  ret = yr_rules_scan_file(rules, fname, scan_callback, &results, fast_mode, timeout);
  if (ret == ERROR_COULD_NOT_OPEN_FILE)
    rb_raise(error_ScanError, "Could not open file: '%s'", fname);
  else if (ret != 0)
    rb_raise(error_ScanError, "A error occurred while scanning: %s", 
        ((ret > MAX_SCAN_ERROR)? "unknown error" : SCAN_ERRORS[ret]));

  return results;
}


/* 
 * call-seq:
 *      rules.scan_string(buf) -> Array
 *
 * Scans a ruby string using the compiled rules supplied
 * with either compile_file or compile_string (or both).
 *
 * @param [String] buf The string buffer to scan with yara.
 *
 * @return [Yara::Match] An array of Yara::Match objects found in the string.
 *
 * @raise [Yara::ScanError] Raised if an error occurs while scanning the string.
 */
VALUE rules_scan_string(VALUE self, VALUE rb_dat) {
  YR_COMPILER *ctx;
  VALUE results;
  char *buf;
  size_t buflen;
  int ret;

  Check_Type(rb_dat, T_STRING);
  buf = RSTRING_PTR(rb_dat);
  buflen = RSTRING_LEN(rb_dat);

  results = rb_ary_new();

  Data_Get_Struct(self, YR_COMPILER, ctx);

  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(ctx, &rules))
    rb_raise(error_ScanError, "Error retrieving rules"); 

  int fast_mode = 0;	// TODO
  int timeout = 0;	// TODO
  ret = yr_rules_scan_mem(rules, (unsigned char*)buf, buflen, scan_callback, &results, fast_mode, timeout);
  if (ret != 0)
    rb_raise(error_ScanError, "A error occurred while scanning: %s", 
        ((ret > MAX_SCAN_ERROR)? "unknown error" : SCAN_ERRORS[ret]));

  return results;
}

/*
 * Document-class: Yara::Rules
 *
 * Encapsulates a Yara context against which you can compile rules and
 * scan inputs.
 */
void init_Rules() {
  VALUE module_Yara = rb_define_module("Yara");

  class_Rules = rb_define_class_under(module_Yara, "Rules", rb_cObject);
  rb_define_alloc_func(class_Rules, rules_allocate);

  rb_define_method(class_Rules, "compile_file", rules_compile_file, -1);
  rb_define_method(class_Rules, "compile_string", rules_compile_string, -1);
  rb_define_method(class_Rules, "current_namespace", rules_current_namespace, 0);
  rb_define_method(class_Rules, "scan_file", rules_scan_file, 1);
  rb_define_method(class_Rules, "scan_string", rules_scan_string, 1);
}

