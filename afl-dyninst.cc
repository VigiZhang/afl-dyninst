#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <set>
#include <vector>
#include <climits>

#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"


using namespace std;
using namespace Dyninst;

#define SIZE 256

int verbose = 0;

const char *functions[] = {"main", "_main", "_initproc", "_init", "start", "_start", NULL};

const char *aflStubLib = "libafl-stub.so";

static const char *USAGE = "-dfvxD -i <in_binary> -o <out_binary> -l <linked_library> -e <ep_address> -E <exit_address> -s <number> -S <filter_function> -m <size> \n \
  -i: input binary \n \
  -o: output binary \n \
  -d: do not instrument the binary, only supplied libraries \n \
  -l: linked library to instrument (repeat for more than one) \n \
  -r: runtime library to instrument (repeat for more than one) \n \
  -e: entry point address to patch (required for stripped binaries) \n \
  -E: exit point - force exit(0) at this address (repeat for more than one) \n \
  -s: number of initial basic blocks to skip in binary \n \
  -m: minimum size of a basic block to instrument \n \
  -f: try to fix a dyninst bug that leads to crashes (loss of 20%% performance) \n \
  -S: do not instrument this function (repeat for more than one) \n \
  -D: instrument only a simple fork server and also forced exit functions \n \
  -x: experimental performance modes (can be set up to three times) \n \
        level 1: ~40-50%% improvement \n \
        level 2: ~100%% vs normal, ~40%% vs level 1 \n \
        level 3: ~110%% vs normal, ~5%% vs level 2 \n \
      level 3 replaces how basic block coverage works and can be tried if \n \
      normal mode or level 1 or 2 lead to crashes randomly.\n \
  -v: verbose output\n";
static const char *OPT_STR = "fi:o:l:e:E:vs:dr:m:S:Dx";

char *originalBinary = NULL;
char *instrumentedBinary = NULL;
char *entryPointName = NULL;

Address entryPoint;
set<string> instrumentLibraries;
set<string> runtimeLibraries;
set<string> skipAddresses;
set<unsigned long> exitAddresses;
unsigned int bbSkip = 0;
unsigned int bbMinSize = 1;
unsigned long insertion_bb = 0;
int performance = 0;

BPatch_function *initAflForkServer;
BPatch_function *bbCallback;
BPatch_function *save_rdi;
BPatch_function *restore_rdi;
BPatch_function *forceCleanExit;

bool parseOptions(int argc, char* argv[]) {
  int c;
  while ((c = getopt(argc, argv, OPT_STR)) != -1) {
    switch ((char) c) {
      case 'i':
        originalBinary = optarg;
        instrumentLibraries.insert(optarg);
        break;
      case 'o':
        instrumentedBinary = optarg;
        break;
      case 'v':
        verbose++;
        break;
      case 'e':
        if ((entryPoint = strtoul(optarg, NULL, 16)) < 0x1000)
          entryPointName = optarg;
        break;
      case 'l':
        instrumentLibraries.insert(optarg);
        break;
      case 'S':
        skipAddresses.insert(optarg);
        break;
      case 's':
        bbSkip = atoi(optarg);
        break;
      case 'm':
        bbMinSize = atoi(optarg);
        break;
      case 'x':
        performance++;
        break;
      case 'E':
        exitAddresses.insert(strtoul(optarg, NULL, 16));
        break;
      case 'r':
        runtimeLibraries.insert(optarg);
        break;
      default:
        cerr << "Usage: " << argv[0] << USAGE;;
        return false;
    }
  }

  if (originalBinary == NULL) {
    cerr << "Input binary is required!" << endl;
    cerr << "Usage: " << argv[0] << USAGE;
    return false;
  }

  if (instrumentedBinary == NULL) {
    cerr << "Output binary is required!" << endl;
    cerr << "Usage: " << argv[0] << USAGE;
    return false;
  }

  return true;
}

BPatch_function *findFuncByName(BPatch_image *appImage, char *funcName) {
  vector<BPatch_function *> funcs;

  if (NULL == appImage->findFunction(funcName, funcs) || !funcs.size() || NULL == funcs[0]) {
    cerr << "Failed to find " << funcName << " function." << endl;
    return NULL;
  }

  return funcs[0];
}

// insert callback to address
bool insertCallbackToAddr(BPatch_addressSpace *app, BPatch_image *appImage, BPatch_function *instFunc, BPatch_module *module, BPatch_function *func) {
  vector<BPatch_point *> points;
  vector<BPatch_point *> *funcEntry = func->findPoint(BPatch_entry);
  BPatchSnippetHandle *handle;

  if (NULL == funcEntry) {
    cerr << "Failed to find entry for function." << endl;
    return false;
  }

  vector<BPatch_snippet *> instArgs;
  BPatch_funcCallExpr instExpr(*instFunc, instArgs);

  cout << "Inserting callback." << endl;
  handle = app->insertSnippet(instExpr, *funcEntry, BPatch_callBefore, BPatch_lastSnippet);

  if (!handle) {
    cerr << "Failed to insert callback." << endl;
    return false;
  }

  return true;
}

// insert bb callback
bool insertBBCallback(BPatch_addressSpace *app, BPatch_image *appImage, BPatch_function *instFunc, BPatch_function *func, char *funcName, unsigned int *bbIndex) {
  unsigned short randID;
  BPatch_flowGraph *fg = func->getCFG();

  if (!fg) {
    cerr << "Failed to find CFG for function " << funcName << endl;
    return false;
  }

  set<BPatch_basicBlock *> blocks;
  fg->getAllBasicBlocks(blocks);

  set<BPatch_basicBlock *>::iterator blockIter;
  for (blockIter = blocks.begin(); blockIter != blocks.end(); ++blockIter) {
    if (*bbIndex < bbSkip || (*blockIter)->size() < bbMinSize) {
      (*bbIndex)++;
      continue;
    }

    if (performance >= 1) {
      if ((*blockIter)->isEntryBlock() == false) {
        bool single_path = true;

        vector<BPatch_basicBlock *> sources;
        (*blockIter)->getSources(sources);
        for (unsigned int i = 0; i < sources.size() && single_path == false; ++i) {
          vector<BPatch_basicBlock *> targets;
          sources[i]->getTargets(targets);
          if (targets.size() > 1) {
            single_path = false;
          }
        }
        if (single_path) {
          continue;
        }
      }
    }

    BPatch_point *bbEntry = (*blockIter)->findEntryPoint();
    unsigned long address = (*blockIter)->getStartAddress();
    randID = rand() % USHRT_MAX;
    if (verbose >= 1) {
      cout << "Instrumenting basic block 0x" << hex << address << " of " << funcName << " with size " << dec 
        << (*blockIter)->size() << " with random id " << randID << "/0x" << hex << randID << endl;
    }

    if (NULL == bbEntry) {
      cerr << "Failed to find entry for basic block at 0x" << hex << address << endl;
      (*bbIndex)++;
      continue;
    }

    BPatchSnippetHandle *handle;
    vector<BPatch_snippet *> instArgs_void;
    vector<BPatch_snippet *> instArgs;
    BPatch_constExpr bbId(randID);
    instArgs.push_back(&bbId);

    BPatch_funcCallExpr instExpr1(*save_rdi, instArgs_void);
    BPatch_funcCallExpr instExpr2(*instFunc, instArgs);
    BPatch_funcCallExpr instExpr3(*restore_rdi, instArgs_void);

    app->insertSnippet(instExpr1, *bbEntry, BPatch_callBefore, BPatch_firstSnippet);
    handle = app->insertSnippet(instExpr2, *bbEntry, BPatch_callBefore);
    app->insertSnippet(instExpr3, *bbEntry, BPatch_callBefore, BPatch_lastSnippet);

    if (!handle) {
      cerr << "Failed to insert instrumention in basic block at 0x" << hex << address << endl;
      (*bbIndex)++;
      continue;
    } else {
      insertion_bb++;
    }
    (*bbIndex)++;
  }

  return true;
}

int main(int argc, char* argv[]) {

  cout << "afl-dyninst - instrument binary with afl-stub by dyninst" << endl;
  
  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0 || strncmp(argv[1], "--h", 3) == 0) {
    cout << "Usage: " << argv[0] << USAGE;
    return 0;
  }

  if (!parseOptions(argc, argv)) {
    return EXIT_FAILURE;
  }

  BPatch bpatch;

  BPatch_binaryEdit *appBin = bpatch.openBinary(originalBinary, instrumentLibraries.size() != 1);
  if (appBin == NULL) {
    cerr << "Failed to open binary" << endl;
    return EXIT_FAILURE;
  }

  BPatch_addressSpace *app = appBin;
  BPatch_image *appImage = app->getImage();

  vector<BPatch_module *> *modules = appImage->getModules();
  vector<BPatch_module *>::iterator moduleIter;
  vector<BPatch_function *> *funcsInModule;
  BPatch_module *defaultModule = NULL;
  BPatch_module *firstModule = NULL;
  string defaultModuleName;

  char *func2patch = NULL;

  if (defaultModuleName.empty()) {
    for (int i = 0; functions[i] != NULL && func2patch == NULL; ++i) {
      for (moduleIter = modules->begin(); moduleIter != modules->end(); ++moduleIter) {
        vector<BPatch_function *>::iterator funcsIter;
        char moduleName[SIZE];

        if (firstModule == NULL) {
          firstModule = (*moduleIter);
        }

        (*moduleIter)->getName(moduleName, SIZE);
        if (verbose >= 2) {
          cout << "Looking for init function " << functions[i] << " in " << moduleName << endl;
        }

        funcsInModule = (*moduleIter)->getProcedures();
        for (funcsIter = funcsInModule->begin(); funcsIter != funcsInModule->end(); ++funcsIter) {
          char funcName[SIZE];

          (*funcsIter)->getName(funcName, SIZE);
          if (verbose >= 3 && i == 0) {
            cout << "module: " << moduleName << " function: " << funcName << endl;
          }

          if (string(funcName) == string(functions[i])) {
            func2patch = (char *) functions[i];
            defaultModuleName = string(moduleName);
            defaultModule = (*moduleIter);
            if (verbose >= 1) {
              cout << "Found " << func2patch << " in " << moduleName << endl;
            }
            break;
          }
        }
        if (!defaultModuleName.empty()) {
          break;
        }
      }
      if (func2patch != NULL) {
        break;
      }
    }
  }

  if (defaultModuleName.empty()) {
    defaultModuleName = string(originalBinary).substr(string(originalBinary).find_last_of("\\/") + 1);
  }
  if (defaultModule == NULL) {
    defaultModule = firstModule;
  }

  if (!app->loadLibrary(aflStubLib)) {
    cerr << "Failed to open instrumentation library " << aflStubLib << endl;
    cerr << "It needs to be located in the current working directory." << endl;
    return EXIT_FAILURE;
  }

  initAflForkServer = findFuncByName(appImage, (char *) "afl_stub_initAflForkServer");
  bbCallback = findFuncByName(appImage, (char *) "afl_stub_bbCallback");
  forceCleanExit = findFuncByName(appImage, (char *) "afl_stub_forceCleanExit");
  save_rdi = findFuncByName(appImage, (char *) "afl_stub_save_rdi");
  restore_rdi = findFuncByName(appImage, (char *) "afl_stub_restore_rdi");

  if (!initAflForkServer || !bbCallback || !forceCleanExit || !save_rdi || !restore_rdi) {
    cerr << "Instrumentation library lacks callbacks!" << endl;
    return EXIT_FAILURE;
  }

  // find funcToPatch (from entrypoint or init)
  BPatch_function *funcToPatch = NULL;
  if (entryPoint == 0 && entryPointName == NULL) {
    if (func2patch == NULL) {
      cerr << "Couldn't locate _init, specify entry point manually with -e 0xaddr" << endl;
      return EXIT_FAILURE;
    }

    vector<BPatch_function *> funcs;
    defaultModule->findFunction(func2patch, funcs);
    if (!funcs.size()) {
      cerr << "Couldn't locate _init, specify entry point manually with -e 0xaddr" << endl;
      return EXIT_FAILURE;
    }

    funcToPatch = funcs[0];
  } else {
    if (entryPointName != NULL) {
      for (moduleIter = modules->begin(); moduleIter != modules->end() && funcToPatch == 0; ++moduleIter) {
        vector<BPatch_function *> funcs;
        (*moduleIter)->findFunction(entryPointName, funcs);
        if (funcs.size() > 0) {
          char moduleName[SIZE];
          funcToPatch = funcs[0];
          defaultModule = (*moduleIter);
          defaultModule->getName(moduleName, SIZE);
          defaultModuleName = string(moduleName);
          cout << "Found entrypoint " << entryPointName << " in module " << moduleName << endl;
          break;
        }
      }
    }
    if (!funcToPatch) {
      if (verbose > 1) {
        cout << "Looking for entrypoint " << (char*) entryPoint << endl;
      }
      funcToPatch = defaultModule->findFunctionByEntry(entryPoint);
      if (!funcToPatch && defaultModule != firstModule) {
        funcToPatch = firstModule->findFunctionByEntry(entryPoint);
        if (funcToPatch) {
          defaultModule = firstModule;
        }
      }
      if (!funcToPatch) {
        if (verbose > 1) {
          cout << "OK we did not find the entrypoint so far, lets dig deeper ..." << endl;
        }
        for (moduleIter = modules->begin(); moduleIter != modules->end() && funcToPatch != NULL; ++ moduleIter) {
          funcToPatch = (*moduleIter)->findFunctionByEntry(entryPoint);
          if (funcToPatch) {
            defaultModule = (*moduleIter);
          }
        }
      }
      if (funcToPatch && verbose >= 1) {
        char moduleName[SIZE];

        defaultModule->getName(moduleName, SIZE);
        defaultModuleName = string(moduleName);
        cout << "Found entrypoint " << entryPoint << " in module " << moduleName << endl;
      }
    }
  }

  if (!funcToPatch) {
    cerr << "Couldn't find proper function to patch." << endl;
    cerr << "Try: readelf -ls " << originalBinary << " | egrep 'Entry|FUNC.*GLOBAL.*DEFAULT' | egrep -v '@|UND'" << endl;
    return EXIT_FAILURE;
  }

  // insert afl init fork server stub
  if (!insertCallbackToAddr(app, appImage, initAflForkServer, defaultModule, funcToPatch)) {
    cerr << "Could not insert callback at given function point." << endl;
    return EXIT_FAILURE;
  }

  unsigned int bbIndex = 0;
  // insert bb coverage stub
  for (moduleIter = modules->begin(); moduleIter != modules->end(); ++moduleIter) {
    char moduleName[SIZE];
    (*moduleIter)->getName(moduleName, SIZE);
    if ((*moduleIter)->isSharedLib()) {
      if (instrumentLibraries.find(moduleName) == instrumentLibraries.end()) {
        cout << "Skipping library: " << moduleName << endl;
        continue;
      }
    }
    
    cout << "Instrumenting module: " << moduleName << endl;
    vector<BPatch_function *> *funcs = (*moduleIter)->getProcedures();
    vector<BPatch_function *>::iterator funcIter;

    for (funcIter = funcs->begin(); funcIter != funcs->end(); ++funcIter) {
      char funcName[SIZE];
      int do_patch = 1;

      (*funcIter)->getName(funcName, SIZE);
      if (string(funcName) == string("_init") || string(funcName) == string("__libc_csu_init") || string(funcName) == string("_start"))
        continue;

      if (!skipAddresses.empty()) {
        set<string>::iterator skipIter;
        for (skipIter = skipAddresses.begin(); skipIter != skipAddresses.end() && do_patch == 1; ++skipIter) {
          if (*skipIter == string(funcName)) {
            do_patch = 0;
          }
        }
        if (do_patch == 0) {
          cout << "Skipping instrumenting function " << funcName << endl;
          continue;
        }
      }
      insertBBCallback(app, appImage, bbCallback, (*funcIter), funcName, &bbIndex);
    }
  }

  // insert exit procedure
  if (!exitAddresses.empty()) {
    cout << "Instrumenting forced exit addresses." << endl;
    set<unsigned long>::iterator exitIter;

    for (exitIter = exitAddresses.begin(); exitIter != exitAddresses.end(); ++exitIter) {
      if (*exitIter > 0 && (signed long) *exitIter != -1) {
        funcToPatch = defaultModule->findFunctionByEntry(*exitIter);
        if (!funcToPatch) {
          cerr << "Could not find entry point 0x" << hex << *exitIter << " (continuing)" << endl;
        } else {
          if (!insertCallbackToAddr(app, appImage, forceCleanExit, defaultModule, funcToPatch)) {
            cerr << "Could not insert force clean exit callback at 0x" << hex << *exitIter << " (continuing)" << endl;
          }
        }
      }
    }
  }

  cout << "Saving the instrumented binary to " << instrumentedBinary << " ..." << endl;
  if (!appBin->writeFile(instrumentedBinary)) {
    cerr << "Failed to write output file: " << instrumentedBinary << endl;
    return EXIT_FAILURE;
  }

  if (!runtimeLibraries.empty()) {
    cout << "Instrumenting runtime libraries." << endl;
  }

  printf("Did a total of %lu basick block insertions.\n", insertion_bb);
  cout << "All done! Happy fuzzing!" << endl;
  return EXIT_SUCCESS;
}
