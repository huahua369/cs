# CMakeList.txt: uvtest 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("uvtest")
 
#设置库文件输出目录
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out/bin)
#设置执行文件输出目录
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out/bin)
#设置连接库lib目录
link_directories(${PROJECT_SOURCE_DIR}/out/bin)
link_directories(${VCPKG_LIB_PATH})
 
set(client_n test_client)
set(server_n test_server)
# 将源代码添加到此项目的可执行文件。
set(src_c 
	"src/cs.cpp" 
	"src/test_client.cpp" 
)
set(src_s 
	"src/cs.cpp" 
	"src/test_server.cpp" 
)

add_executable(${server_n} ${src_s})
add_executable(${client_n} ${src_c})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${server_n} PROPERTY CXX_STANDARD 20)
  set_property(TARGET ${client_n} PROPERTY CXX_STANDARD 20)
endif()

find_package(unofficial-libuv CONFIG REQUIRED)
#连接动态库
set(st 
	#uv
	unofficial::libuv::libuv
)
target_link_libraries(${server_n}  PRIVATE ${st})
target_link_libraries(${client_n}  PRIVATE ${st})
# TODO: 如有需要，请添加测试并安装目标。
