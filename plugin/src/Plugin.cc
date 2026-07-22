#include "config.h"
#include "Plugin.h"
#include "Analyzer.h"

#include <iostream>

#include <zeek/analyzer/Component.h>

namespace zeek::plugin::mms {

Plugin plugin; 

zeek::plugin::Configuration Plugin::Configure()
{
	zeek::plugin::Configuration config;

    //声明插件元信息，名称/描述/版本信息；
    //Zeek加载插件时，知道有一个叫 `OSS::MMS` 的插件。
	config.name = "OSS::MMS";
	config.description = "";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;

    static const std::string simple_name="MMS";
    static const std::string iso_name=util::canonify_name("ISO:1.0.9506.2.1");

    //向Zeek注册协议分析器，注册了两个名字，指向同一个 Analyzer 实现。
    //lambda 工厂函数：当 Zeek 需要在这条连接上启用该 analyzer 时，调用此工厂函数创建analyzer实例
    //当协议栈识别到 MMS 或 ISO:1.0.9506.2.1 时，就为这条连接创建一个mms分析器实例来处理后续 MMS 数据。
    AddComponent(
        new zeek::analyzer::Component(
            simple_name,
            [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {return new Analyzer(simple_name.c_str(), c);}
        )
    );
    AddComponent(
        new zeek::analyzer::Component(
            iso_name,
            [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {return new Analyzer(iso_name.c_str(), c);}
        )
    );

	return config;
}
 
} // namespace zeek::plugin::mms
