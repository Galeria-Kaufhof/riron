require 'spec_helper'

describe Riron do

  let(:salt_size) { 256 }
  let(:salt) { Riron.generate_salt(salt_size) }

  describe 'generate_salt' do

    subject { salt.length }

    context 'for 256 salt bits' do
      it { should eq(64) }
    end

    context 'for 128 salt bits' do
      let(:salt_size) { 128 }
      it { should eq(32) }
    end
  end

  describe 'generate_key' do
    let(:subject) { Riron.generate_key("geheim", salt, Riron::AES_128_CBC, Riron::DEFAULT_ENCRYPTION_OPTIONS.iterations) }
    it 'generates a key with the correct length' do
      expect(subject.length).to eq(16)
    end
  end

  describe 'seal & unseal' do
    let(:message)  { 'Secret message' }
    let(:password) { 'some_secret_password' }
    let(:login)    { 'some_login_id' }

    let(:sealed) do
      Riron.seal(message, login, password, Riron::DEFAULT_ENCRYPTION_OPTIONS, Riron::DEFAULT_INTEGRITY_OPTIONS)
    end

    let(:unsealed) do
      Riron.unseal(sealed, unlocker, Riron::DEFAULT_ENCRYPTION_OPTIONS, Riron::DEFAULT_INTEGRITY_OPTIONS)
    end

    subject { unsealed }

    let(:unlocker) { {login => password} }
    it { should eq message }

    context 'providing extra options in unlocker' do
      let(:unlocker) { {login => password, foo: :bar} }
      it { should eq message }
    end

    context 'providing password only' do
      let(:unlocker) { password }
      it { should eq message }
    end

    context 'unsealing a token create with the C version of iron' do
      let(:sealed) { "Fe26.1*123*8cfbb22695939029a676a31c650437bfa4c29151f5203e237114bdae216ad47f*tQRDEMleUpP33iKzOo20BQ*cCjSg-XY1eLRzJDicCvPfw*b8cf9fbf957b5b7ada6cb94f883557004e9fc31d77cc0702a080bbe4179d02c6*-jg0jPk4u5XO2WUqnZu_LAFgAjtWPHu_IFmRxeNqaKA" }
      let(:unlocker) { { "123" => "password" } }
      it { should eq message }
    end
  end
end
