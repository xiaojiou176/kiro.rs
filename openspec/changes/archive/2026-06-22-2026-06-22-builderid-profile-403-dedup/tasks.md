# Tasks

- [x] TDD: 写 is_definitive_profile_unsupported 的 4 个测试(403→true, not-supported body→true, 5xx→false, 429→false)
- [x] 实现 helper + list_available_profiles definitive_unsupported 分支
- [x] cargo test 全绿(547 passed)
- [x] runtime 验: id22 发 4 发全 200 / 0 条 profileArn 失败警告 / 出站照发占位符 profileArn = 去重生效
