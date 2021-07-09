<?php declare(strict_types=1);

namespace Stefna\SecretsManager\Provider\AwsSsm;

use AsyncAws\SecretsManager\Exception\ResourceNotFoundException;
use AsyncAws\Ssm\Enum\ParameterType;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Stefna\SecretsManager\Exceptions\SecretNotFoundException;
use Stefna\SecretsManager\Provider\ProviderInterface;
use Stefna\SecretsManager\Values\Secret;

final class AwsSsmProvider implements ProviderInterface
{
	/** @var SsmClient */
	private $client;
	/** @var array<string, Secret> */
	private $data = [];

	public function __construct(SsmClient $client)
	{
		$this->client = $client;
	}

	public function putSecret(Secret $secret, ?array $options = []): Secret
	{
		if (!is_scalar($secret->getValue())) {
			throw new \BadMethodCallException('Parameter store don\'t support complex types');
		}

		$options['Name'] = $secret->getKey();
		$options['Value'] = $secret->getValue();
		$options['Overwrite'] = $options['Overwrite'] ?? true;
		$options['Type'] = ParameterType::SECURE_STRING;

		$this->client->putParameter($options);

		return $secret;
	}

	public function deleteSecret(Secret $secret, ?array $options = []): void
	{
		$this->client->deleteParameter([
			'Name' => $secret->getKey(),
		]);
		unset($this->data[$secret->getKey()]);
	}

	public function getSecret(string $key, ?array $options = []): Secret
	{
		if (isset($this->data[$key])) {
			return $this->data[$key];
		}
		try {
			$parameters = $this->client->getParametersByPath([
				'Path' => $key,
				'Recursive' => true,
				'WithDecryption' => true,
			]);

			$currentValue = [];
			$keyLength = strlen($key);
			$count = 0;
			/** @var Parameter $parameter */
			foreach ($parameters as $parameter) {
				$count++;
				$paramKey = (string)$parameter->getName();
				$subKey = substr($paramKey, $keyLength + 1);
				$keyParts = explode('/', $subKey);
				$value = (string)$parameter->getValue();
				$currentValue = $this->buildNestedArray($currentValue, $keyParts, $value);

				$secret = new Secret(
					$key,
					$value
				);
				$this->data[$parameter->getName()] = $secret;
			}
			if ($count === 1) {
				$currentValue = array_pop($currentValue);
			}
			return $this->data[$key] = new Secret($key, $currentValue);
		}
		catch (ResourceNotFoundException $e) {
			throw SecretNotFoundException::withKey($key);
		}
	}


	/**
	 * @param array<string, mixed> $data
	 * @param string[] $keys
	 * @param mixed $value
	 * @return array<string, mixed>
	 */
	private function buildNestedArray(array $data, array $keys, $value): array
	{
		$rootPtr = &$data;
		$lastKey = array_pop($keys);
		while ($currentKey = array_shift($keys)) {
			if (!array_key_exists($currentKey, $data)) {
				$data[$currentKey] = [];
			}
			$data = &$data[$currentKey];
		}

		$data[$lastKey] = $value;
		return $rootPtr;
	}
}
