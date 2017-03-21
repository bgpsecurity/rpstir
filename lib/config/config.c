#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "configlib/types/bool.h"
#include "configlib/types/deprecated.h"
#include "configlib/types/enum.h"
#include "configlib/types/path.h"
#include "configlib/types/sscanf.h"
#include "configlib/types/string_cvt.h"
#include "util/logging.h"
#include "util/stringutils.h"


/** All available config options */
static const struct config_option config_options[] = {
    // CONFIG_RPKI_PORT
    {
     "RPKIPort",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_uint16_t,
     config_type_sscanf_converter_inverse,
     &config_type_sscanf_inverse_arg_uint16_t,
     free,
     NULL, NULL,
     "7344"},

    // CONFIG_DATABASE
    {
     "Database",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     config_type_string_converter_inverse, NULL,
     free,
     NULL, NULL,
     NULL}, // NULL here means this option must be filled in by a config file

    // CONFIG_DATABASE_USER
    {
     "DatabaseUser",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     config_type_string_converter_inverse, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DATABASE_PASSWORD
    {
     "DatabasePassword",
     false,
     config_type_string_converter, &config_type_string_arg_optional,
     config_type_string_converter_inverse, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DATABASE_DSN
    {
     "DatabaseDSN",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     NULL, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_TRUST_ANCHOR_LOCATORS
    {
     "TrustAnchorLocators",
     true,
     config_type_path_converter, NULL,
     config_type_path_converter_inverse, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_LOG_LEVEL
    {
     "LogLevel",
     false,
     config_type_enum_converter, &config_type_enum_arg_log_level,
     NULL, NULL,
     config_type_enum_free,
     NULL, NULL,
     "LOG_INFO"},

    // CONFIG_DOWNLOAD_CONCURRENCY
    {
     "DownloadConcurrency",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_size_t,
     config_type_sscanf_converter_inverse,
     &config_type_sscanf_inverse_arg_size_t,
     free,
     NULL, NULL,
     "24"},

    // CONFIG_RPKI_RTR_RETENTION_HOURS
    {
     "RpkiRtrRetentionHours",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_size_t,
     NULL, NULL,
     free,
     NULL, NULL,
     "96"},

    // CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN
    {
     "RPKIAllowStaleValidationChain",
     false,
     config_type_deprecated_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     ""},

    // CONFIG_RPKI_ALLOW_NO_MANIFEST
    {
     "RPKIAllowNoManifest",
     false,
     config_type_bool_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "yes"},

    // CONFIG_RPKI_ALLOW_STALE_CRL
    {
     "RPKIAllowStaleCRL",
     false,
     config_type_bool_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "yes"},

    // CONFIG_RPKI_ALLOW_STALE_MANIFEST
    {
     "RPKIAllowStaleManifest",
     false,
     config_type_bool_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "yes"},

    // CONFIG_RPKI_ALLOW_NOT_YET
    {
     "RPKIAllowNotYet",
     false,
     config_type_bool_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "no"},

    // CONFIG_RPKI_EXTRA_PUBLICATION_POINTS
    {
     "RPKIExtraPublicationPoints",
     true,
     config_type_string_converter, &config_type_string_arg_mandatory,
     NULL, NULL,
     free,
     NULL, NULL,
     ""}, // "" here means the empty array

    // CONFIG_NEW_VERSION_CHECK
    {
     "NewVersionCheck",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     config_type_string_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"https://rpki.bbn.com/check-version?package=" PACKAGE_NAME
     "&version=" PACKAGE_VERSION "\""},

    // CONFIG_NEW_VERSION_CHECK_CA_CERT
    {
     "NewVersionCheckCACert",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     config_type_string_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"" PKGDATADIR "/version-server-ca.pem\""},

    // CONFIG_TEMPLATE_CA_CERT
    {
     "TemplateCACert",
     false,
     config_type_path_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "\"" TEMPLATESDIR "/ca_template.cer\""},

    // CONFIG_TEMPLATE_EE_CERT
    {
     "TemplateEECert",
     false,
     config_type_path_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "\"" TEMPLATESDIR "/ee_template.cer\""},

    // CONFIG_TEMPLATE_CRL
    {
     "TemplateCRL",
     false,
     config_type_path_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "\"" TEMPLATESDIR "/crl_template.crl\""},

    // CONFIG_TEMPLATE_MANIFEST
    {
     "TemplateManifest",
     false,
     config_type_path_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "\"" TEMPLATESDIR "/M.man\""},

    // CONFIG_TEMPLATE_ROA
    {
     "TemplateROA",
     false,
     config_type_path_converter, NULL,
     NULL, NULL,
     free,
     NULL, NULL,
     "\"" TEMPLATESDIR "/R.roa\""},

    // CONFIG_RPKI_CACHE_DIR
    {
     "RPKICacheDir",
     false,
     config_type_path_converter, NULL,
     config_type_path_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"" PKGCACHEDIR "\""},

    // CONFIG_VRS_CACHE_DIR
    {
      "VRSCacheDir",
      false,
      config_type_path_converter, NULL,
      config_type_path_converter_inverse, NULL,
      free,
      NULL, NULL,
      "\"" VRSCACHEDIR "\""},

    // CONFIG_LOG_DIR
    {
     "LogDir",
     false,
     config_type_path_converter, NULL,
     config_type_path_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"" PKGLOGDIR "\""},

    // CONFIG_LOG_RETENTION
    {
     "LogRetention",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_size_t,
     config_type_sscanf_converter_inverse,
     &config_type_sscanf_inverse_arg_size_t,
     free,
     NULL, NULL,
     "9"},

    // CONFIG_RPKI_STATISTICS_DIR
    {
     "RPKIStatisticsDir",
     false,
     config_type_path_converter, NULL,
     config_type_path_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"" PKGVARLIBDIR "/statistics\""},
};


bool my_config_load(
    void)
{
    const char * user_home = getenv("HOME");
    if (user_home == NULL)
    {
        LOG(LOG_ERR, "environment variable HOME not set");
        return false;
    }

    char * user_conf_file = NULL;
    size_t user_conf_file_len = strlen(user_home) + strlen("/") +
                                strlen("." PACKAGE_NAME ".conf") + 1;

    user_conf_file = malloc(user_conf_file_len);
    if (user_conf_file == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

    xsnprintf(user_conf_file, user_conf_file_len, "%s/.%s.conf", user_home,
              PACKAGE_NAME);

    char const * const default_config_files[] = {
        user_conf_file,
        PACKAGE_SYS_CONF_FILE,
        NULL
    };

    bool ret = config_load(CONFIG_NUM_OPTIONS, config_options,
                           getenv(CONFIG_ENV_VAR), default_config_files);

    free(user_conf_file);

    if (ret)
    {
        SET_LOG_LEVEL(CONFIG_LOG_LEVEL_get());
    }

    return ret;
}
