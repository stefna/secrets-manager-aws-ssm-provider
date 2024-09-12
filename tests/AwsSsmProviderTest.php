<?php declare(strict_types=1);

namespace Stefna\SecretsManager\Provider\AwsSsm\Tests;

use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\Ssm\Result\DeleteParameterResult;
use AsyncAws\Ssm\Result\GetParametersByPathResult;
use AsyncAws\Ssm\Result\PutParameterResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use PHPUnit\Framework\TestCase;
use Stefna\SecretsManager\Provider\AwsSsm\AwsSsmProvider;
use Stefna\SecretsManager\Values\Secret;

final class AwsSsmProviderTest extends TestCase
{
	public function testRetrieveValue(): void
	{
		$key = '/test/MyTestDatabaseSecret';
		$client = $this->getMockBuilder(SsmClient::class)
			->disableOriginalConstructor()
			->onlyMethods(['getParametersByPath'])
			->getMock();

		$value = 'secret';
		$result = ResultMockFactory::create(GetParametersByPathResult::class, [
			'Parameters' => [
				new Parameter([
					'Name' => $key,
					'Type' => 'String',
					'Value' => $value,
					'Version' => 1,
				]),
			],
		]);
		$client
			->expects($this->once())
			->method('getParametersByPath')
			->with($this->callback(function (array $args) use ($key) {
				return $args['Path'] === $key;
			}))->willReturn($result);

		$provider = new AwsSsmProvider($client);

		$secret = $provider->getSecret($key);
		$this->assertSame($value, $secret->getValue());
	}

	public function testGetNestedValues(): void
	{
		$key = '/test/db';
		$client = $this->getMockBuilder(SsmClient::class)
			->disableOriginalConstructor()
			->onlyMethods(['getParametersByPath'])
			->getMock();

		$result = ResultMockFactory::create(GetParametersByPathResult::class, [
			'Parameters' => [
				new Parameter([
					'Name' => $key . '/name',
					'Type' => 'String',
					'Value' => 'dbName',
					'Version' => 1,
				]),
				new Parameter([
					'Name' => $key . '/extra/test1',
					'Type' => 'String',
					'Value' => 'test1',
					'Version' => 1,
				]),
				new Parameter([
					'Name' => $key . '/extra/test2',
					'Type' => 'String',
					'Value' => 'test2',
					'Version' => 1,
				]),
				new Parameter([
					'Name' => $key . '/user',
					'Type' => 'String',
					'Value' => 'dbUser',
					'Version' => 1,
				]),
			],
		]);
		$client
			->expects($this->once())
			->method('getParametersByPath')
			->with($this->callback(function (array $args) use ($key) {
				return $args['Path'] === $key;
			}))->willReturn($result);

		$provider = new AwsSsmProvider($client);

		$secret = $provider->getSecret($key);
		$this->assertSame([
			'name' => 'dbName',
			'extra' => [
				'test1' => 'test1',
				'test2' => 'test2',
			],
			'user' => 'dbUser'
		], $secret->getValue());
		$this->assertSame('dbUser', $provider->getSecret($key . '/user')->getValue());
	}

	public function testPutSecret(): void
	{
		$testValue = 'value';
		$testKey = 'test-key';
		$client = $this->getMockBuilder(SsmClient::class)
			->disableOriginalConstructor()
			->onlyMethods(['putParameter'])
			->getMock();

		$result = ResultMockFactory::create(PutParameterResult::class);
		$client
			->expects($this->once())
			->method('putParameter')
			->with($this->callback(function (array $args) use ($testKey, $testValue) {
				if ($args['Name'] !== $testKey) {
					return false;
				}
				if ($args['Value'] !== $testValue) {
					return false;
				}
				if ($args['Type'] !== 'SecureString') {
					return false;
				}
				return true;
			}))->willReturn($result);

		$provider = new AwsSsmProvider($client);

		$provider->putSecret(new Secret($testKey, $testValue));
	}

	public function testDeleteSecretPersisting(): void
	{
		$testKey = 'test-key';
		$client = $this->getMockBuilder(SsmClient::class)
			->disableOriginalConstructor()
			->onlyMethods(['deleteParameter'])
			->getMock();

		$result = ResultMockFactory::create(DeleteParameterResult::class);
		$client
			->expects($this->once())
			->method('deleteParameter')
			->with($this->callback(function (array $args) use ($testKey) {
				return $args['Name'] === $testKey;
			}))->willReturn($result);

		$provider = new AwsSsmProvider($client);
		$provider->deleteSecret(new Secret($testKey, ''));
	}
}
