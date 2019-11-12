#!/usr/bin/env python
#
# Copyright 2016 Mozilla
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This script will read a CSV of modules from Socorro, and try to retrieve
# missing symbols from Microsoft's symbol server. It honors a blacklist
# (blacklist.txt) of symbols that are known to be from our applications,
# and it maintains its own list of symbols that the MS symbol server
# doesn't have (skiplist.txt).
#
# The script also depends on having write access to the directory it is
# installed in, to write the skiplist text file.

from aiofile import AIOFile, LineReader
from aiohttp import ClientSession, ClientTimeout
from aiohttp.connector import TCPConnector
import argparse
import asyncio
import sys
import os
import shutil
import time
import logging
from collections import defaultdict
from tempfile import mkdtemp
from urllib.parse import urljoin
from urllib.parse import quote
import zipfile


# Just hardcoded here
MICROSOFT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols/"
USER_AGENT = "Microsoft-Symbol-Server/6.3.0.0"
MOZILLA_SYMBOL_SERVER = (
    "https://s3-us-west-2.amazonaws.com/org.mozilla.crash-stats.symbols-public/v1/"
)
MISSING_SYMBOLS_URL = "https://symbols.mozilla.org/missingsymbols.csv?microsoft=only"
HEADERS = {"User-Agent": USER_AGENT}
SYM_SRV = "SRV*{}*https://msdl.microsoft.com/download/symbols"
TIMEOUT = 7200
RETRIES = 10


log = logging.getLogger()


def get_type(data):
    # PDB v7
    if data.startswith(b"Microsoft C/C++ MSF 7.00"):
        return "pdb-v7"
    # PDB v2
    if data.startswith(b"Microsoft C/C++ program database 2.00"):
        return "pdb-v2"
    # DLL
    if data.startswith(b"MZ"):
        return "dll"
    # CAB
    if data.startswith(b"MSCF"):
        return "cab"

    return "unknown"


async def server_has_file(client, server, filename):
    """
    Send the symbol server a HEAD request to see if it has this symbol file.
    """
    url = urljoin(server, quote(filename))
    for _ in range(RETRIES):
        try:
            async with client.head(url, headers=HEADERS, allow_redirects=True) as resp:
                if resp.status == 200 and (
                    (
                        "microsoft" in server
                        and resp.headers["Content-Type"] == "application/octet-stream"
                    )
                    or "mozilla" in server
                ):
                    log.debug(f"File exists: {url}")
                    return True
                else:
                    return False
        except Exception as e:
            # Sometimes we've SSL errors or disconnections... so in such a situation just retry
            log.debug(f"Error with {url}: retry")
            log.exception(e)
            await asyncio.sleep(0.5)

    log.debug(f"Too much retries (HEAD) for {url}: give up.")
    return False


async def fetch_file(client, server, filename):
    """
    Fetch the file from the server
    """
    url = urljoin(server, quote(filename))
    log.debug(f"Fetch url: {url}")
    for _ in range(RETRIES):
        try:
            async with client.get(url, headers=HEADERS, allow_redirects=True) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    typ = get_type(data)
                    if typ == "unknown":
                        # try again
                        await asyncio.sleep(0.5)
                    elif typ == "pdb-v2":
                        # too old: skip it
                        log.debug(f"PDB v2 (skipped because too old): {url}")
                        return None
                    else:
                        return data
                else:
                    log.error(f"Cannot get data (status {resp.status}) for {url}: ")
        except Exception as e:
            log.debug(f"Error with {url}")
            log.exception(e)
            await asyncio.sleep(0.5)

    log.debug(f"Too much retries (GET) for {url}: give up.")
    return None


def write_skiplist(skiplist):
    with open("skiplist.txt", "w") as sf:
        for (debug_id, debug_file) in skiplist.items():
            sf.write("%s %s\n" % (debug_id, debug_file))


async def fetch_missing_symbols(u):
    log.info("Trying missing symbols from %s" % u)
    async with ClientSession() as client:
        async with client.get(u, headers=HEADERS) as resp:
            # just skip the first line since it contains column headers
            data = await resp.text()
            return data.splitlines()[1:]


async def get_list(filename, info):
    alist = set()
    if os.path.exists(filename):
        async with AIOFile(filename, "r") as In:
            async for line in LineReader(In):
                line = line.rstrip()
                alist.add(line)
    log.debug(f"{info} contains {len(alist)} items")

    return alist


async def get_skiplist():
    skiplist = {}
    skipcount = 0
    path = "skiplist.txt"
    if os.path.exists(path):
        async with AIOFile(path, "r") as In:
            async for line in LineReader(In):
                line = line.strip()
                if line == "":
                    continue
                s = line.split(None, 1)
                if len(s) != 2:
                    continue
                debug_id, debug_file = s
                skiplist[debug_id] = debug_file.lower()
                skipcount += 1
    log.debug(f"Skiplist contains {skipcount} items")

    return skiplist


def get_missing_symbols(missing_symbols, skiplist, blacklist):
    modules = defaultdict(set)
    stats = {"blacklist": 0, "skiplist": 0}
    for line in missing_symbols:
        line = line.rstrip()
        bits = line.split(",")
        if len(bits) < 2:
            continue
        pdb, debug_id = bits[:2]
        code_file, code_id = None, None
        if len(bits) >= 4:
            code_file, code_id = bits[2:4]
        if pdb and debug_id and pdb.endswith(".pdb"):
            if pdb.lower() in blacklist:
                stats["blacklist"] += 1
                continue

            if skiplist.get(debug_id) != pdb.lower():
                modules[pdb].add((debug_id, code_file, code_id))
            else:
                stats["skiplist"] += 1
                # We've asked the symbol server previously about this,
                # so skip it.
                log.debug("%s/%s already in skiplist", pdb, debug_id)

    return modules, stats


async def collect_info(client, filename, debug_id, code_file, code_id):
    pdb_path = os.path.join(filename, debug_id, filename)
    sym_path = os.path.join(filename, debug_id, filename.replace(".pdb", "") + ".sym")

    has_pdb = await server_has_file(client, MICROSOFT_SYMBOL_SERVER, pdb_path)
    has_code = is_there = False
    if has_pdb and not await server_has_file(client, MOZILLA_SYMBOL_SERVER, sym_path):
        has_code = await server_has_file(
            client, MICROSOFT_SYMBOL_SERVER, f"{code_file}/{code_id}/{code_file}"
        )
    elif has_pdb:
        # if the file is on moz sym server no need to do anything
        is_there = True
        has_pdb = False

    return (filename, debug_id, code_file, code_id, has_pdb, has_code, is_there)


async def check_x86_file(path):
    async with AIOFile(path, "rb") as In:
        chunk = await In.read(32)
        if chunk.startswith(b"MODULE windows x86 "):
            return True
    return False


async def run_command(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    err = err.decode().strip()

    return err


async def dump_module(
    output, symcache, filename, debug_id, code_file, code_id, has_code, dump_syms
):
    sym_path = os.path.join(filename, debug_id, filename.replace(".pdb", "") + ".sym")
    output_path = os.path.join(output, sym_path)
    sym_srv = SYM_SRV.format(symcache)

    if has_code:
        cmd = f"{dump_syms} {code_file} --code-id {code_id} --store {output} --symbol-server '{sym_srv}' --verbose error"
    else:
        cmd = f"{dump_syms} {filename} --debug-id {debug_id} --store {output} --symbol-server '{sym_srv}' --verbose error"

    err = await run_command(cmd)

    if err:
        log.error(f"Error with {cmd}")
        log.error(err)
        return 1

    if not has_code and not await check_x86_file(output_path):
        log.debug(f"x86_64 binary {code_file}/{code_id} required")
        return 2

    log.info(f"Successfully dumped: {filename}/{debug_id}")
    return sym_path


async def dump_helper(output, symcache, modules, dump_syms):
    tasks = []
    for filename, debug_id, code_file, code_id, has_code in modules:
        tasks.append(
            dump_module(
                output,
                symcache,
                filename,
                debug_id,
                code_file,
                code_id,
                has_code,
                dump_syms,
            )
        )

    return await asyncio.gather(*tasks)


def dump(output, symcache, modules, dump_syms):
    res = asyncio.run(dump_helper(output, symcache, modules, dump_syms))
    file_index = {x for x in res if isinstance(x, str)}
    stats = {
        "dump_error": sum(1 for x in res if x == 1),
        "no_bin": sum(1 for x in res if x == 2),
    }

    return file_index, stats


async def collect_helper(modules):
    loop = asyncio.get_event_loop()
    tasks = []
    connector = TCPConnector(limit=100, limit_per_host=20)
    async with ClientSession(
        loop=loop, timeout=ClientTimeout(total=TIMEOUT), connector=connector
    ) as client:
        for filename, ids in modules.items():
            for debug_id, code_file, code_id in ids:
                tasks.append(
                    collect_info(client, filename, debug_id, code_file, code_id)
                )

        return await asyncio.gather(*tasks)


def collect(modules):
    res = asyncio.run(collect_helper(modules))
    to_dump = []
    stats = {"no_pdb": 0, "is_there": 0}
    for filename, debug_id, code_file, code_id, has_pdb, has_code, is_there in res:
        if not has_pdb:
            if is_there:
                stats["is_there"] += 1
            else:
                stats["no_pdb"] += 1
                log.info(f"No pdb for {filename}/{debug_id}")
            continue

        log.info(
            f"To dump: {filename}/{debug_id}, {code_file}/{code_id} and has_code = {has_code}"
        )
        to_dump.append((filename, debug_id, code_file, code_id, has_code))

    log.info(f"Collected {len(to_dump)} files to dump")

    return to_dump, stats


async def fetch_and_write(output, client, filename, file_id):
    path = os.path.join(filename, file_id, filename)
    data = await fetch_file(client, MICROSOFT_SYMBOL_SERVER, path)

    if not data:
        return False

    output_dir = os.path.join(output, filename, file_id)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_path = os.path.join(output_dir, filename)
    async with AIOFile(output_path, "wb") as Out:
        await Out.write(data)

    return True


async def fetch_all_helper(output, modules):
    loop = asyncio.get_event_loop()
    tasks = []
    connector = TCPConnector(limit=100, limit_per_host=20)
    async with ClientSession(
        loop=loop, timeout=ClientTimeout(total=TIMEOUT), connector=connector
    ) as client:
        for filename, debug_id, code_file, code_id, has_code in modules:
            tasks.append(fetch_and_write(output, client, filename, debug_id))
            if has_code:
                tasks.append(fetch_and_write(output, client, code_file, code_id))

        return await asyncio.gather(*tasks)


def fetch_all(output, modules):
    res = asyncio.run(fetch_all_helper(output, modules))
    res = iter(res)
    fetched_modules = []
    for filename, debug_id, code_file, code_id, has_code in modules:
        fetched_pdb = next(res)
        if has_code:
            has_code = next(res)
        if fetched_pdb:
            fetched_modules.append((filename, debug_id, code_file, code_id, has_code))
    return fetched_modules


def get_base_data(url):
    async def helper(url):
        return await asyncio.gather(
            fetch_missing_symbols(url),
            # Symbols that we know belong to us, so don't ask Microsoft for them.
            get_list("blacklist.txt", "Blacklist"),
            # Symbols that we know belong to Microsoft, so don't skiplist them.
            get_list("known-microsoft-symbols.txt", "Known Microsoft symbols"),
            # Symbols that we've asked for in the past unsuccessfully
            get_skiplist(),
        )

    return asyncio.run(helper(url))


def gen_zip(output, output_dir, file_index):
    if not file_index:
        return

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
        for f in file_index:
            z.write(os.path.join(output_dir, f), f)
    log.info(f"Wrote zip as {output}")


def retry_run(cmd, *arg):
    for _ in range(RETRIES // 2):
        try:
            return cmd(*arg)
        except OSError as e:
            # Sometimes for any reasons we've "Too much open files"
            # So wait and try again
            log.exception(e)
            time.sleep(10)


def main():
    parser = argparse.ArgumentParser(
        description="Fetch missing symbols from Microsoft symbol server"
    )
    parser.add_argument(
        "--missing-symbols",
        type=str,
        help="missing symbols URL",
        default=MISSING_SYMBOLS_URL,
    )
    parser.add_argument("zip", type=str, help="output zip file")
    parser.add_argument(
        "--dump-syms",
        type=str,
        help="dump_syms path",
        default=os.environ.get("DUMP_SYMS_PATH"),
    )

    args = parser.parse_args()

    assert bool(args.dump_syms), "dump_syms path is empty"

    logging.basicConfig(level=logging.DEBUG)
    aiohttp_logger = logging.getLogger("aiohttp.client")
    aiohttp_logger.setLevel(logging.DEBUG)
    log.info("Started")

    missing_symbols, blacklist, known_ms_symbols, skiplist = get_base_data(
        args.missing_symbols
    )

    modules, stats_skipped = get_missing_symbols(missing_symbols, skiplist, blacklist)
    total = len(modules) + stats_skipped["blacklist"] + stats_skipped["skiplist"]

    symbol_path = mkdtemp("symsrvfetch")
    temp_path = mkdtemp(prefix="symcache")

    modules, stats_collect = retry_run(collect, modules)
    modules = retry_run(fetch_all, temp_path, modules)

    file_index, stats_dump = dump(symbol_path, temp_path, modules, args.dump_syms)

    gen_zip(args.zip, symbol_path, file_index)

    shutil.rmtree(symbol_path, True)
    shutil.rmtree(temp_path, True)

    if not file_index:
        log.info(
            f"No symbols downloaded: {total} considered, "
            f"{stats_collect['is_there']} already present, {stats_skipped['blacklist']} in blacklist, {stats_skipped['skiplist']} skipped, {stats_collect['no_pdb']} not found, "
            f"{stats_dump['dump_error']} not processed"
        )

        write_skiplist(skiplist)
        sys.exit(0)

    # Write out our new skip list
    write_skiplist(skiplist)
    log.info(f"Stored {len(file_index)} symbol files")
    log.info("Finished, exiting")


if __name__ == "__main__":
    main()
