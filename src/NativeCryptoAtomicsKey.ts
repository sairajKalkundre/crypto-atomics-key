import type { NativeModule } from 'craby-modules';
import { NativeModuleRegistry } from 'craby-modules';

interface Spec extends NativeModule {

  setCredentials(password: string, dbPath: string): void;

// Starts the multi-threaded gen + encrypt process
  generateAndStore(password: string, dbPath: string): void;

  // Unlocks the key into memory
  unlock_and_get_key(password: string, dbPath: string): Promise<string>;

  // Returns 0-100 progress of the Argon2 task
  getDerivationProgress(): number;

  getActiveKeyHex(): string;

  // Signs a hex message if the vault is unlocked
  signMessage(message: string): string;
}

export default NativeModuleRegistry.getEnforcing<Spec>('CryptoAtomicsKey');
