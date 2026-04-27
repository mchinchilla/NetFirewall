using Xunit;

namespace NetFirewall.Tests.Infra;

/// <summary>
/// Marker for every test class that needs a real Postgres instance. xUnit
/// instantiates <see cref="PostgresFixture"/> once per collection and shares
/// it across all classes that carry <c>[Collection("Postgres")]</c>.
///
/// Tests inside the same collection run sequentially within their assembly
/// — that's the price of sharing a stateful resource and the reason we
/// reset the schema explicitly inside each test instead of relying on
/// xUnit's per-class isolation.
/// </summary>
[CollectionDefinition("Postgres")]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture> { }
