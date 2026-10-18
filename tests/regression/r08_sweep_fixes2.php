<?php
/**
 * r08_sweep_fixes2.php — locks the AI-error reflected-XSS fix (#3/#4/#5). A hostile/echoing AI provider
 * could return HTML/JS in error.message; three module JS handlers inject it into innerHTML. The structural
 * fix strips tags at the source in mspro_ai307_sanitize_provider_message (every UI consumer gets tag-free
 * text). (The #6/#7/#8/#9/#10 symlink/scope fixes share smpro_path_safe, locked in r07; #8 fa_allowed_target
 * additionally rejects is_link + requires realpath===path — covered by inspection since its regex demands
 * real /home paths that can't be created in-sandbox.)
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('modules/ai_providers_engine.php');   // mspro_ai307_sanitize_provider_message (router-free)

ok(function_exists('mspro_ai307_sanitize_provider_message'), 'AI provider-error sanitizer loaded');

$x = mspro_ai307_sanitize_provider_message('HTTP 400: <img src=x onerror=fetch("/scripts2/add_user")>request denied');
hasnt($x, '<img', '#3/4/5 AI error: <img> tag stripped');
hasnt($x, '<', '#3/4/5 AI error: NO angle brackets survive (cannot become DOM in innerHTML)');
hasnt($x, 'onerror', '#3/4/5 AI error: the onerror handler text is gone with the tag');
has($x, 'request denied', '#3/4/5 AI error: human-readable text preserved');

$svg = mspro_ai307_sanitize_provider_message('<svg onload=window.__xss=1>quota exceeded</svg>');
hasnt($svg, '<svg', '#3/4/5 AI error: <svg onload> stripped');
has($svg, 'quota exceeded', '#3/4/5 AI error: message text kept');

// the original key-redaction still works after adding strip_tags
hasnt(mspro_ai307_sanitize_provider_message('auth error sk-ABCDEFGH123456789'), 'sk-ABCDEFGH123456789', '#3/4/5 AI error: still redacts sk- API keys');
hasnt(mspro_ai307_sanitize_provider_message('rejected: Bearer abcdef1234567890XYZ'), 'abcdef1234567890XYZ', '#3/4/5 AI error: still redacts Bearer tokens');
