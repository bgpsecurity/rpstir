#ifndef UTIL_CONFIG_H_
#define UTIL_CONFIG_H_


#define RPSTIR_CONFIG_FILE "rpstir.config"


/* =============================================================================
 * @brief Forces a reload of the config file.
------------------------------------------------------------------------------*/
void config_refresh(void);


/* =============================================================================
 * @note The caller must free 'value' if it is returned.
 * @return 1 if a value is returned.
 *         0 if no value is returned.
 *        -1 on error; no value returned.
------------------------------------------------------------------------------*/
int config_get_str(char **value, size_t max_len, char const *key);


/* =============================================================================
 * @return 1 if a value is returned.
 *         0 if no value is returned.
------------------------------------------------------------------------------*/
int config_get_int(int *val, char const *key);


/* =============================================================================
 * @return 1 if a value is returned.
 *         0 if no value is returned.
------------------------------------------------------------------------------*/
int config_get_bool(int *val, char const *key);


#endif  // UTIL_CONFIG_H_
