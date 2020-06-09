/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2020 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include "src/operators/inspect_file.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <string>
#include <iostream>

#include "src/operators/operator.h"
#include "src/utils/system.h"

namespace modsecurity {
namespace operators {

bool InspectFile::init(const std::string &param2, std::string *error) {
    std::istream *iss;
    std::string err;
    std::string err_lua;

    m_file = utils::find_resource(m_param, param2, &err);
    iss = new std::ifstream(m_file, std::ios::in);

    if (((std::ifstream *)iss)->is_open() == false) {
        error->assign("Failed to open file: " + m_param + ". " + err);
        delete iss;
        return false;
    }

    if (engine::Lua::isCompatible(m_file, &m_lua, &err_lua) == true) {
        m_isScript = true;
    }

    delete iss;
    return true;
}


bool InspectFile::evaluate(Transaction *transaction,
    const std::string &parameters) {
    /**
     *  FIXME: This kind of external execution could be part of the utils.
     *         (a) External execution is also expected by exec action.
     *         (b) One day, this should be workable on windows as well.
     *         (c) Audit log may depend on external execution.
     *
     **/
    if (m_isScript) {
        return m_lua.run(transaction, parameters);
    }

    std::string command(m_param);
    std::string commandWithParameters(command + " " + parameters);

    ms_dbg_a(transaction, 8, "Executing: " + command + \
        ". With parameters: " + parameters);


    int ret = access(command.c_str(), F_OK);
    if (ret != 0) {
        if (errno == ENOENT) {
            ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
                ". File not found.");
            return false;
        }

        if (errno == EACCES) {
            ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
                ". Permission denied.");
            return false;
        }

        ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
            ". " + strerror(errno));
        return false;
    }

    ret = access(command.c_str(), X_OK);
    if (ret != 0) {
        if (errno == ENOENT) {
            ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
                ". File not found.");
            return false;
        }

        if (errno == EACCES) {
            ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
                ". Permission denied.");
            return false;
        }

        ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
            ". " + strerror(errno));
        return false;
    }

    FILE *in = popen(commandWithParameters.c_str(), "r");
    if (in == NULL) {
        ms_dbg_a(transaction, 8, "Failed to execute: " + command + \
            ". " + strerror(errno));
        return false;
    }

    std::stringstream s;
    char buff[512];
    while (fgets(buff, sizeof(buff), in) != NULL) {
        s << buff;
    }

    if (pclose(in) == -1) {
        ms_dbg_a(transaction, 8, "Failed during the execute of: " + command + \
            ". " + strerror(errno));
    }

    std::string res = s.str();
    ms_dbg_a(transaction, 8, "Process output: " + res);

    if (res.size() > 1 && res.at(0) != '1') {
        return true; /* match */
    }

    /* no match */
    return false;
}


}  // namespace operators
}  // namespace modsecurity
