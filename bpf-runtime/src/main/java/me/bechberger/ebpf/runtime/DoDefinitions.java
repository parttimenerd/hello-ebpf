/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with do
 */
@java.lang.SuppressWarnings("unused")
public final class DoDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __do_adjtimex(Ptr<tk_data> tkd, Ptr<__kernel_timex> txc,
      Ptr<adjtimex_result> result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_fstatfs(@Unsigned int fd, Ptr<compat_statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_getrusage(int who, Ptr<compat_rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_ia32_clone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, @Unsigned long tls_val,
      Ptr<java.lang.Integer> child_tidptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_ia32_fstat64(@Unsigned int fd, Ptr<stat64> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_ia32_fstatat64($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static long __do_compat_sys_ia32_fstatat64(@Unsigned int dfd, String filename,
      Ptr<stat64> statbuf, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_ia32_lstat64((const u8 *)$arg1, $arg2)")
  public static long __do_compat_sys_ia32_lstat64(String filename, Ptr<stat64> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_ia32_stat64((const u8 *)$arg1, $arg2)")
  public static long __do_compat_sys_ia32_stat64(String filename, Ptr<stat64> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_ioctl(@Unsigned int fd, @Unsigned int cmd,
      @Unsigned @OriginalName("compat_ulong_t") int arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_keyctl(@Unsigned int option, @Unsigned int arg2,
      @Unsigned int arg3, @Unsigned int arg4, @Unsigned int arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_mq_getsetattr($arg1, (const struct compat_mq_attr *)$arg2, $arg3)")
  public static long __do_compat_sys_mq_getsetattr(@OriginalName("mqd_t") int mqdes,
      Ptr<compat_mq_attr> u_mqstat, Ptr<compat_mq_attr> u_omqstat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_newfstat(@Unsigned int fd, Ptr<compat_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_newfstatat($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static long __do_compat_sys_newfstatat(@Unsigned int dfd, String filename,
      Ptr<compat_stat> statbuf, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_newlstat((const u8 *)$arg1, $arg2)")
  public static long __do_compat_sys_newlstat(String filename, Ptr<compat_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_newstat((const u8 *)$arg1, $arg2)")
  public static long __do_compat_sys_newstat(String filename, Ptr<compat_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_rt_sigreturn((const struct pt_regs *)$arg1)")
  public static long __do_compat_sys_rt_sigreturn(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_sigreturn((const struct pt_regs *)$arg1)")
  public static long __do_compat_sys_sigreturn(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_socketcall(int call, Ptr<java.lang. @Unsigned Integer> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_compat_sys_statfs((const u8 *)$arg1, $arg2)")
  public static long __do_compat_sys_statfs(String pathname, Ptr<compat_statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_sysinfo(Ptr<compat_sysinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_ustat(@Unsigned int dev, Ptr<compat_ustat> u) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_wait4(@OriginalName("compat_pid_t") int pid,
      Ptr<java.lang. @Unsigned @OriginalName("compat_uint_t") Integer> stat_addr, int options,
      Ptr<compat_rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_compat_sys_waitid(int which, @OriginalName("compat_pid_t") int pid,
      Ptr<compat_siginfo> infop, int options, Ptr<compat_rusage> uru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __do_fast_syscall_32(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int __do_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int __do_huge_pmd_anonymous_page(
      Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mount> __do_loopback(Ptr<path> old_path, int recurse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __do_notify(Ptr<mqueue_inode_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __do_once_done(Ptr<java.lang. @OriginalName("bool") Boolean> done,
      Ptr<static_key_true> once_key, Ptr<java.lang. @Unsigned Long> flags, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __do_once_sleepable_done(Ptr<java.lang. @OriginalName("bool") Boolean> done,
      Ptr<static_key_true> once_key, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __do_once_sleepable_start(
      Ptr<java.lang. @OriginalName("bool") Boolean> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __do_once_start(Ptr<java.lang. @OriginalName("bool") Boolean> done,
      Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __do_pipe_flags(Ptr<java.lang.Integer> fd, Ptr<Ptr<file>> files, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_proc_dointvec($arg1, (const struct ctl_table *)$arg2, $arg3, $arg4, $arg5, $arg6, (int (*)(_Bool*, long unsigned int*, int*, int, void*))$arg7, $arg8)")
  public static int __do_proc_dointvec(Ptr<?> tbl_data, Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<?> conv, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_proc_douintvec($arg1, (const struct ctl_table *)$arg2, $arg3, $arg4, $arg5, $arg6, (int (*)(long unsigned int*, unsigned int*, int, void*))$arg7, $arg8)")
  public static int __do_proc_douintvec(Ptr<?> tbl_data, Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<?> conv, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_proc_doulongvec_minmax($arg1, (const struct ctl_table *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static int __do_proc_doulongvec_minmax(Ptr<?> data, Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long convmul,
      @Unsigned long convdiv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_semtimedop($arg1, $arg2, $arg3, (const struct timespec64 *)$arg4, $arg5)")
  public static long __do_semtimedop(int semid, Ptr<sembuf> sops, @Unsigned int nsops,
      Ptr<timespec64> timeout, Ptr<ipc_namespace> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __do_set_cpus_allowed(Ptr<task_struct> p, Ptr<affinity_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __do_softirq() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long __do_splice(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_in, Ptr<file> out,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_add_key((const u8 *)$arg1, (const u8 *)$arg2, (const void *)$arg3, $arg4, $arg5)")
  public static long __do_sys_add_key(String _type, String _description, Ptr<?> _payload,
      @Unsigned long plen, @OriginalName("key_serial_t") int ringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_adjtimex(Ptr<__kernel_timex> txc_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_adjtimex_time32(Ptr<old_timex32> utp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_brk(@Unsigned long brk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_capget(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> dataptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_capset($arg1, (const struct __user_cap_data_struct*)$arg2)")
  public static long __do_sys_capset(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_clock_adjtime((const int)$arg1, $arg2)")
  public static long __do_sys_clock_adjtime(@OriginalName("clockid_t") int which_clock,
      Ptr<__kernel_timex> utx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_clock_adjtime32(@OriginalName("clockid_t") int which_clock,
      Ptr<old_timex32> utp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_clone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, Ptr<java.lang.Integer> child_tidptr,
      @Unsigned long tls) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_clone3(Ptr<clone_args> uargs, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_copy_file_range(int fd_in,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_in, int fd_out,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_delete_module((const u8 *)$arg1, $arg2)")
  public static long __do_sys_delete_module(String name_user, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_fanotify_init(@Unsigned int flags, @Unsigned int event_f_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_file_getattr($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static long __do_sys_file_getattr(int dfd, String filename, Ptr<file_attr> ufattr,
      @Unsigned long usize, @Unsigned int at_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_file_setattr($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static long __do_sys_file_setattr(int dfd, String filename, Ptr<file_attr> ufattr,
      @Unsigned long usize, @Unsigned int at_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_flock(@Unsigned int fd, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_fork((const struct pt_regs *)$arg1)")
  public static long __do_sys_fork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_fsconfig($arg1, $arg2, (const u8 *)$arg3, (const void *)$arg4, $arg5)")
  public static long __do_sys_fsconfig(int fd, @Unsigned int cmd, String _key, Ptr<?> _value,
      int aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_fsmount(int fs_fd, @Unsigned int flags, @Unsigned int attr_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_fstat(@Unsigned int fd, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_fstatfs(@Unsigned int fd, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_fstatfs64(@Unsigned int fd, @Unsigned long sz, Ptr<statfs64> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_futex_requeue(Ptr<futex_waitv> waiters, @Unsigned int flags,
      int nr_wake, int nr_requeue) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_futex_waitv(Ptr<futex_waitv> waiters, @Unsigned int nr_futexes,
      @Unsigned int flags, Ptr<__kernel_timespec> timeout, @OriginalName("clockid_t") int clockid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_getcwd(String buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getegid((const struct pt_regs *)$arg1)")
  public static long __do_sys_getegid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getegid16((const struct pt_regs *)$arg1)")
  public static long __do_sys_getegid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_geteuid((const struct pt_regs *)$arg1)")
  public static long __do_sys_geteuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_geteuid16((const struct pt_regs *)$arg1)")
  public static long __do_sys_geteuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getgid((const struct pt_regs *)$arg1)")
  public static long __do_sys_getgid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getgid16((const struct pt_regs *)$arg1)")
  public static long __do_sys_getgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_gethostname(String name, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getpgrp((const struct pt_regs *)$arg1)")
  public static long __do_sys_getpgrp(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getpid((const struct pt_regs *)$arg1)")
  public static long __do_sys_getpid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getppid((const struct pt_regs *)$arg1)")
  public static long __do_sys_getppid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_getpriority(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_getrusage(int who, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_gettid((const struct pt_regs *)$arg1)")
  public static long __do_sys_gettid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getuid((const struct pt_regs *)$arg1)")
  public static long __do_sys_getuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_getuid16((const struct pt_regs *)$arg1)")
  public static long __do_sys_getuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_init_module($arg1, $arg2, (const u8 *)$arg3)")
  public static long __do_sys_init_module(Ptr<?> umod, @Unsigned long len, String uargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_inotify_init((const struct pt_regs *)$arg1)")
  public static long __do_sys_inotify_init(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_io_uring_enter($arg1, $arg2, $arg3, $arg4, (const void *)$arg5, $arg6)")
  public static long __do_sys_io_uring_enter(@Unsigned int fd, @Unsigned int to_submit,
      @Unsigned int min_complete, @Unsigned int flags, Ptr<?> argp, @Unsigned long argsz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_io_uring_register(@Unsigned int fd, @Unsigned int opcode, Ptr<?> arg,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_ioprio_get(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_ioprio_set(int which, int who, int ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_kcmp(@OriginalName("pid_t") int pid1, @OriginalName("pid_t") int pid2,
      int type, @Unsigned long idx1, @Unsigned long idx2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_kexec_file_load($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static long __do_sys_kexec_file_load(int kernel_fd, int initrd_fd,
      @Unsigned long cmdline_len, String cmdline_ptr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_keyctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_landlock_create_ruleset((const const struct landlock_ruleset_attr*)$arg1, (const long unsigned int)$arg2, (const unsigned int)$arg3)")
  public static long __do_sys_landlock_create_ruleset(Ptr<landlock_ruleset_attr> attr,
      @Unsigned long size, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_landlock_restrict_self((const int)$arg1, (const unsigned int)$arg2)")
  public static long __do_sys_landlock_restrict_self(int ruleset_fd, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_listmount((const struct mnt_id_req *)$arg1, $arg2, $arg3, $arg4)")
  public static long __do_sys_listmount(Ptr<mnt_id_req> req, Ptr<java.lang. @Unsigned Long> mnt_ids,
      @Unsigned long nr_mnt_ids, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_lstat((const u8 *)$arg1, $arg2)")
  public static long __do_sys_lstat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_membarrier(int cmd, @Unsigned int flags, int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_memfd_create((const u8 *)$arg1, $arg2)")
  public static long __do_sys_memfd_create(String uname, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_mlockall(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_move_mount($arg1, (const u8 *)$arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static long __do_sys_move_mount(int from_dfd, String from_pathname, int to_dfd,
      String to_pathname, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_mq_getsetattr($arg1, (const struct mq_attr *)$arg2, $arg3)")
  public static long __do_sys_mq_getsetattr(@OriginalName("mqd_t") int mqdes, Ptr<mq_attr> u_mqstat,
      Ptr<mq_attr> u_omqstat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_mq_unlink((const u8 *)$arg1)")
  public static long __do_sys_mq_unlink(String u_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_mremap(@Unsigned long addr, @Unsigned long old_len,
      @Unsigned long new_len, @Unsigned long flags, @Unsigned long new_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_msync(@Unsigned long start, @Unsigned long len, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_munlockall((const struct pt_regs *)$arg1)")
  public static long __do_sys_munlockall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_newfstat(@Unsigned int fd, Ptr<stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_newfstatat($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static long __do_sys_newfstatat(int dfd, String filename, Ptr<stat> statbuf, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_newlstat((const u8 *)$arg1, $arg2)")
  public static long __do_sys_newlstat(String filename, Ptr<stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_newstat((const u8 *)$arg1, $arg2)")
  public static long __do_sys_newstat(String filename, Ptr<stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_newuname(Ptr<new_utsname> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_ni_syscall((const struct pt_regs *)$arg1)")
  public static long __do_sys_ni_syscall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_open_tree_attr($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static long __do_sys_open_tree_attr(int dfd, String filename, @Unsigned int flags,
      Ptr<mount_attr> uattr, @Unsigned long usize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_pause((const struct pt_regs *)$arg1)")
  public static long __do_sys_pause(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_perf_event_open(Ptr<perf_event_attr> attr_uptr,
      @OriginalName("pid_t") int pid, int cpu, int group_fd, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_pivot_root((const u8 *)$arg1, (const u8 *)$arg2)")
  public static long __do_sys_pivot_root(String new_root, String put_old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_pkey_alloc(@Unsigned long flags, @Unsigned long init_val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_prctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_prlimit64($arg1, $arg2, (const struct rlimit64 *)$arg3, $arg4)")
  public static long __do_sys_prlimit64(@OriginalName("pid_t") int pid, @Unsigned int resource,
      Ptr<rlimit64> new_rlim, Ptr<rlimit64> old_rlim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_process_madvise($arg1, (const struct iovec *)$arg2, $arg3, $arg4, $arg5)")
  public static long __do_sys_process_madvise(int pidfd, Ptr<iovec> vec, @Unsigned long vlen,
      int behavior, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_process_mrelease(int pidfd, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_reboot(int magic1, int magic2, @Unsigned int cmd, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_remap_file_pages(@Unsigned long start, @Unsigned long size,
      @Unsigned long prot, @Unsigned long pgoff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_request_key((const u8 *)$arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4)")
  public static long __do_sys_request_key(String _type, String _description, String _callout_info,
      @OriginalName("key_serial_t") int destringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_restart_syscall((const struct pt_regs *)$arg1)")
  public static long __do_sys_restart_syscall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_rt_sigreturn((const struct pt_regs *)$arg1)")
  public static long __do_sys_rt_sigreturn(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_sched_getattr(@OriginalName("pid_t") int pid, Ptr<sched_attr> uattr,
      @Unsigned int usize, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_sched_yield((const struct pt_regs *)$arg1)")
  public static long __do_sys_sched_yield(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_set_mempolicy_home_node(@Unsigned long start, @Unsigned long len,
      @Unsigned long home_node, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_setgroups(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("gid_t") Integer> grouplist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_setgroups16(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("old_gid_t") Short> grouplist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_setns(int fd, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_setpgid(@OriginalName("pid_t") int pid,
      @OriginalName("pid_t") int pgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_setpriority(int which, int who, int niceval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_setsid((const struct pt_regs *)$arg1)")
  public static long __do_sys_setsid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_sgetmask((const struct pt_regs *)$arg1)")
  public static long __do_sys_sgetmask(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_socketcall(int call, Ptr<java.lang. @Unsigned Long> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_stat((const u8 *)$arg1, $arg2)")
  public static long __do_sys_stat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_statfs((const u8 *)$arg1, $arg2)")
  public static long __do_sys_statfs(String pathname, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_statfs64((const u8 *)$arg1, $arg2, $arg3)")
  public static long __do_sys_statfs64(String pathname, @Unsigned long sz, Ptr<statfs64> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_statmount((const struct mnt_id_req *)$arg1, $arg2, $arg3, $arg4)")
  public static long __do_sys_statmount(Ptr<mnt_id_req> req, Ptr<statmount> buf,
      @Unsigned long bufsize, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_swapoff((const u8 *)$arg1)")
  public static long __do_sys_swapoff(String specialfile) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_swapon((const u8 *)$arg1, $arg2)")
  public static long __do_sys_swapon(String specialfile, int swap_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_sync((const struct pt_regs *)$arg1)")
  public static long __do_sys_sync(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_sysinfo(Ptr<sysinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_timerfd_create(int clockid, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_uname(Ptr<old_utsname> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_uretprobe((const struct pt_regs *)$arg1)")
  public static long __do_sys_uretprobe(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_ustat(@Unsigned int dev, Ptr<ustat> ubuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_vfork((const struct pt_regs *)$arg1)")
  public static long __do_sys_vfork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_vhangup((const struct pt_regs *)$arg1)")
  public static long __do_sys_vhangup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__do_sys_vmsplice($arg1, (const struct iovec *)$arg2, $arg3, $arg4)")
  public static long __do_sys_vmsplice(int fd, Ptr<iovec> uiov, @Unsigned long nr_segs,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_wait4(@OriginalName("pid_t") int upid,
      Ptr<java.lang.Integer> stat_addr, int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_sys_waitid(int which, @OriginalName("pid_t") int upid, Ptr<siginfo> infop,
      int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __do_wait(Ptr<wait_opts> wo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> do_accept(Ptr<file> file, Ptr<proto_accept_arg> arg,
      Ptr<sockaddr> upeer_sockaddr, Ptr<java.lang.Integer> upeer_addrlen, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_add_master_key($arg1, $arg2, (const struct fscrypt_key_specifier *)$arg3)")
  public static int do_add_master_key(Ptr<super_block> sb, Ptr<fscrypt_master_key_secret> secret,
      Ptr<fscrypt_key_specifier> mk_spec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_add_mount($arg1, $arg2, (const struct path *)$arg3, $arg4)")
  public static int do_add_mount(Ptr<mount> newmnt, Ptr<mountpoint> mp, Ptr<path> path,
      int mnt_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_adjtimex(Ptr<__kernel_timex> txc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_amd_gpio_irq_handler(int irq, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_anonymous_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_arch_prctl_64(Ptr<task_struct> task, int option, @Unsigned long arg2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_attribute_container_device_trigger_safe($arg1, $arg2, (int (*)(struct attribute_container*, struct device*, struct device*))$arg3, (int (*)(struct attribute_container*, struct device*, struct device*))$arg4)")
  public static int do_attribute_container_device_trigger_safe(Ptr<device> dev,
      Ptr<attribute_container> cont, Ptr<?> fn, Ptr<?> undo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_bind_con_driver((const struct consw *)$arg1, $arg2, $arg3, $arg4)")
  public static int do_bind_con_driver(Ptr<consw> csw, int first, int last, int deflt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_blank_screen(int entering_gfx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_blk_trace_setup(Ptr<request_queue> q, String name,
      @Unsigned @OriginalName("dev_t") int dev, Ptr<block_device> bdev,
      Ptr<blk_user_trace_setup> buts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_boot_cpu(@Unsigned int apicid, @Unsigned int cpu, Ptr<task_struct> idle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_bpf_send_signal(Ptr<irq_work> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_brk_flags(Ptr<vma_iterator> vmi, Ptr<vm_area_struct> vma,
      @Unsigned long addr, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_call_rcu_ttrace(Ptr<bpf_mem_cache> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_check(Ptr<bpf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_check_common(Ptr<bpf_verifier_env> env, int subprog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_check_insn(Ptr<bpf_verifier_env> env,
      Ptr<java.lang. @OriginalName("bool") Boolean> do_print_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_clear_cpu_cap(Ptr<cpuinfo_x86> c, @Unsigned int feature) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_clock_adjtime((const int)$arg1, $arg2)")
  public static int do_clock_adjtime(@OriginalName("clockid_t") int which_clock,
      Ptr<__kernel_timex> ktx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_close_on_exec(Ptr<files_struct> files) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_collect() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_compat_epoll_pwait($arg1, $arg2, $arg3, $arg4, (const struct {\n"
          + "  unsigned int sig[2];\n"
          + "} *)$arg5, $arg6)")
  public static int do_compat_epoll_pwait(int epfd, Ptr<epoll_event> events, int maxevents,
      Ptr<timespec64> timeout, Ptr<compat_sigset_t> sigmask,
      @Unsigned @OriginalName("compat_size_t") int sigsetsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_compat_fcntl64(@Unsigned int fd, @Unsigned int cmd,
      @Unsigned @OriginalName("compat_ulong_t") int arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_compat_futimesat($arg1, (const u8 *)$arg2, $arg3)")
  public static long do_compat_futimesat(@Unsigned int dfd, String filename, Ptr<old_timeval32> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_compat_pselect(int n,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> inp,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> outp,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> exp, Ptr<?> tsp,
      Ptr<compat_sigset_t> sigmask, @Unsigned @OriginalName("compat_size_t") int sigsetsize,
      poll_time_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_compat_select(int n,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> inp,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> outp,
      Ptr<java.lang. @Unsigned @OriginalName("compat_ulong_t") Integer> exp,
      Ptr<old_timeval32> tvp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_compat_sigaltstack((const compat_sigaltstack *)$arg1, $arg2)")
  public static int do_compat_sigaltstack(
      Ptr<@OriginalName("compat_stack_t") compat_sigaltstack> uss_ptr,
      Ptr<@OriginalName("compat_stack_t") compat_sigaltstack> uoss_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_compute_shiftstate() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_con_trol(Ptr<tty_struct> tty, Ptr<vc_data> vc, char c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_con_write($arg1, (const u8 *)$arg2, $arg3)")
  public static int do_con_write(Ptr<tty_struct> tty, Ptr<java.lang.Character> buf, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_copy() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_copy_data_nocache(Ptr<sock> sk, int copy, Ptr<iov_iter> from, String to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_cpu_nanosleep((const int)$arg1, $arg2, (const struct timespec64 *)$arg3)")
  public static int do_cpu_nanosleep(@OriginalName("clockid_t") int which_clock, int flags,
      Ptr<timespec64> rqtp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_cvt_mode((const struct detailed_timing *)$arg1, $arg2)")
  public static void do_cvt_mode(Ptr<detailed_timing> timing, Ptr<?> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_deferred_remove(Ptr<work_struct> w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_dentry_open($arg1, (int (*)(struct inode*, struct file*))$arg2)")
  public static int do_dentry_open(Ptr<file> f, Ptr<?> open) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_detailed_mode((const struct detailed_timing *)$arg1, $arg2)")
  public static void do_detailed_mode(Ptr<detailed_timing> timing, Ptr<?> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_direct_IO(Ptr<dio> dio, Ptr<dio_submit> sdio, Ptr<buffer_head> map_bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_drv_read(Ptr<?> _cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_drv_write(Ptr<?> _cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_dup2(Ptr<files_struct> files, Ptr<file> file, @Unsigned int fd,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_early_exception(Ptr<pt_regs> regs, int trapnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_early_param($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static int do_early_param(String param, String val, String unused, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_emergency_remount(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_emergency_remount_callback(Ptr<super_block> sb, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_enqueue_task(Ptr<rq> rq, Ptr<task_struct> p, @Unsigned long enq_flags,
      int sticky_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_eoi_pirq(Ptr<irq_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_epoll_create(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_epoll_ctl(int epfd, int op, int fd, Ptr<epoll_event> epds,
      boolean nonblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_epoll_wait(int epfd, Ptr<epoll_event> events, int maxevents,
      Ptr<timespec64> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_error_trap(Ptr<pt_regs> regs, long error_code, String str,
      @Unsigned long trapnr, int signr, int sicode, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_established_modes((const struct detailed_timing *)$arg1, $arg2)")
  public static void do_established_modes(Ptr<detailed_timing> timing, Ptr<?> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_eventfd(@Unsigned int count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_exit(long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_faccessat($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int do_faccessat(int dfd, String filename, int mode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_fanotify_mark($arg1, $arg2, $arg3, $arg4, (const u8 *)$arg5)")
  public static int do_fanotify_mark(int fanotify_fd, @Unsigned int flags, @Unsigned long mask,
      int dfd, String pathname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_fast_syscall_32(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_fb_ioctl(Ptr<fb_info> info, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_fb_registered(Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_fbcon_takeover(int show_logo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_fchmodat($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int do_fchmodat(int dfd, String filename,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_fchownat($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int do_fchownat(int dfd, String filename, @Unsigned @OriginalName("uid_t") int user,
      @Unsigned @OriginalName("gid_t") int group, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_fcntl(int fd, @Unsigned int cmd, @Unsigned long arg, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_file_open_root((const struct path *)$arg1, (const u8 *)$arg2, (const struct open_flags *)$arg3)")
  public static Ptr<file> do_file_open_root(Ptr<path> root, String name, Ptr<open_flags> op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_filp_open($arg1, $arg2, (const struct open_flags *)$arg3)")
  public static Ptr<file> do_filp_open(int dfd, Ptr<filename> pathname, Ptr<open_flags> op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_flush_tlb_all(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_free_callbacks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_free_init(Ptr<work_struct> w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_fsync(@Unsigned int fd, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ftruncate(Ptr<file> file, @OriginalName("loff_t") long length, int small) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_futex(Ptr<java.lang. @Unsigned Integer> uaddr, int op, @Unsigned int val,
      Ptr<java.lang. @OriginalName("ktime_t") Long> timeout,
      Ptr<java.lang. @Unsigned Integer> uaddr2, @Unsigned int val2, @Unsigned int val3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_futimesat($arg1, (const u8 *)$arg2, $arg3)")
  public static long do_futimesat(int dfd, String filename, Ptr<__kernel_old_timeval> utimes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_get_acl($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static @OriginalName("ssize_t") long do_get_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name, Ptr<?> kvalue, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_get_dqblk(Ptr<dquot> dquot, Ptr<qc_dqblk> di) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_get_mempolicy(Ptr<java.lang.Integer> policy, Ptr<nodemask_t> nmask,
      @Unsigned long addr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_get_thread_area(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_get_write_access(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<journal_head> jh, int force_copy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_getitimer(int which, Ptr<itimerspec64> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_getpgid(@OriginalName("pid_t") int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_getxattr(Ptr<mnt_idmap> idmap, Ptr<dentry> d,
      Ptr<kernel_xattr_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_global_key_config(Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_group_exit(int exit_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_handle_open(int mountdirfd, Ptr<file_handle> ufh, int open_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_hdmi_vsdb_modes($arg1, (const u8 *)$arg2, $arg3)")
  public static int do_hdmi_vsdb_modes(Ptr<drm_connector> connector, Ptr<java.lang.Character> db,
      char len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_header() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_huge_pmd_anonymous_page(
      Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_huge_pmd_numa_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_huge_pmd_wp_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_huge_zero_wp_pmd(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn do_hvm_evtchn_intr(int irq, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_id_store($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long do_id_store(Ptr<device_driver> drv, String buf,
      @Unsigned long count, id_action action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_idle() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_inferred_modes((const struct detailed_timing *)$arg1, $arg2)")
  public static void do_inferred_modes(Ptr<detailed_timing> timing, Ptr<?> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_init_module(Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_init_real_mode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_initcalls() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_inotify_init(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_int3(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_int80_emulation(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_io_accounting(Ptr<task_struct> task, Ptr<seq_file> m, int whole) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_io_getevents(@Unsigned @OriginalName("aio_context_t") long ctx_id,
      long min_nr, long nr, Ptr<io_event> events, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> do_iommu_domain_alloc(Ptr<device> dev, @Unsigned int flags,
      protection_domain_mode pgtable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ip_getsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ip_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ipv6_getsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ipv6_mcast_group_source(Ptr<sock> sk, int optname, sockptr_t optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_ipv6_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_iter_readv_writev(Ptr<file> filp,
      Ptr<iov_iter> iter, Ptr<java.lang. @OriginalName("loff_t") Long> ppos, int type,
      @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_jit(Ptr<bpf_prog> bpf_prog, Ptr<java.lang.Integer> addrs,
      Ptr<java.lang.Character> image, Ptr<java.lang.Character> rw_image, int oldproglen,
      Ptr<jit_context> ctx, boolean jmp_padding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_journal_get_write_access(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_kern_addr_fault(Ptr<pt_regs> regs, @Unsigned long hw_error_code,
      @Unsigned long address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_kernel_power_off() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_kernel_range_flush(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_kernel_restart(String cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_kexec_load(@Unsigned long entry, @Unsigned long nr_segments,
      Ptr<kexec_segment> segments, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<kimage> do_kimage_alloc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_kmem_cache_create($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int do_kmem_cache_create(Ptr<kmem_cache> s, String name, @Unsigned int size,
      Ptr<kmem_cache_args> args, @Unsigned @OriginalName("slab_flags_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_linkat(int olddfd, Ptr<filename> old, int newdfd, Ptr<filename> _new,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_listmount(Ptr<klistmount> kls, boolean reverse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_lock_mount(Ptr<path> path, Ptr<pinned_mountpoint> pinned, boolean beneath) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_machine_check(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_madvise(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len_in,
      int behavior) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_match_mnt($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4, (const u8 *)$arg5, $arg6, $arg7, $arg8, $arg9)")
  public static int do_match_mnt(Ptr<aa_policydb> policy, @Unsigned int start, String mntpnt,
      String devname, String type, @Unsigned long flags, Ptr<?> data, boolean binary,
      Ptr<aa_perms> perms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_mbind(@Unsigned long start, @Unsigned long len, @Unsigned short mode,
      @Unsigned short mode_flags, Ptr<nodemask_t> nmask, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mcast_group_source(Ptr<sock> sk, int optname, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_md_run(Ptr<mddev> mddev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_md_stop(Ptr<mddev> mddev, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_migrate_pages($arg1, (const struct {\n"
          + "  long unsigned int bits[16];\n"
          + "} *)$arg2, (const struct {\n"
          + "  long unsigned int bits[16];\n"
          + "} *)$arg3, $arg4)")
  public static int do_migrate_pages(Ptr<mm_struct> mm, Ptr<nodemask_t> from, Ptr<nodemask_t> to,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_migrate_range(@Unsigned long start_pfn, @Unsigned long end_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_mincore(@Unsigned long addr, @Unsigned long pages, String vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_misc_fixups(Ptr<bpf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mkdirat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mknodat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mlock(@Unsigned long start, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long do_mmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flags,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags, @Unsigned long pgoff,
      Ptr<java.lang. @Unsigned Long> populate, Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_mmap_read_unlock(Ptr<irq_work> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_mount((const u8 *)$arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int do_mount(String dev_name, String dir_name, String type_page,
      @Unsigned long flags, Ptr<?> data_page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_mount_root((const u8 *)$arg1, (const u8 *)$arg2, (const int)$arg3, (const void *)$arg4)")
  public static int do_mount_root(String name, String fs, int flags, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_move_mount(Ptr<path> old_path, Ptr<path> new_path, mnt_tree_flags_t flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bio> do_mpage_readpage(Ptr<mpage_readpage_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mprotect_pkey(@Unsigned long start, @Unsigned long len, @Unsigned long prot,
      int pkey) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mq_getsetattr(int mqdes, Ptr<mq_attr> _new, Ptr<mq_attr> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_mq_notify($arg1, (const struct sigevent *)$arg2)")
  public static int do_mq_notify(@OriginalName("mqd_t") int mqdes, Ptr<sigevent> notification) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_mq_open((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static int do_mq_open(String u_name, int oflag,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<mq_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mq_timedreceive(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, Ptr<java.lang. @Unsigned Integer> u_msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_mq_timedsend($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int do_mq_timedsend(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, @Unsigned int msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long do_mremap(Ptr<vma_remap_struct> vrm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_mseal(@Unsigned long start, @Unsigned long len_in, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_msg_fill(Ptr<?> dest, Ptr<msg_msg> msg, @Unsigned long bufsz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_msgrcv($arg1, $arg2, $arg3, $arg4, $arg5, (long int (*)(void*, struct msg_msg*, long unsigned int))$arg6)")
  public static long do_msgrcv(int msqid, Ptr<?> buf, @Unsigned long bufsz, long msgtyp, int msgflg,
      Ptr<?> msg_handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_msgsnd(int msqid, long mtype, Ptr<?> mtext, @Unsigned long msgsz,
      int msgflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_munmap(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len,
      Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_name() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_nanosleep(Ptr<hrtimer_sleeper> t, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_netpoll_cleanup(Ptr<netpoll> np) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_new_mount($arg1, (const u8 *)$arg2, $arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static int do_new_mount(Ptr<path> path, String fstype, int sb_flags, int mnt_flags,
      String name, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_no_restart_syscall(Ptr<restart_block> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_nocb_deferred_wakeup(Ptr<rcu_data> rdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_nocb_deferred_wakeup_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_nothing(Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_notify_parent(Ptr<task_struct> tsk, int sig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_notify_parent_cldstop(Ptr<task_struct> tsk, boolean for_ptracer, int why) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_notify_pidfd(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_numa_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_one_broadcast(Ptr<sock> sk, Ptr<netlink_broadcast_data> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_one_initcall(@OriginalName("initcall_t") Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_oops_enter_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_open($arg1, $arg2, (const struct open_flags *)$arg3)")
  public static int do_open(Ptr<nameidata> nd, Ptr<file> file, Ptr<open_flags> op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> do_open_execat(int fd, Ptr<filename> name, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_output_char(char c, Ptr<tty_struct> tty, int space) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_page_mkwrite(Ptr<vm_fault> vmf,
      Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_pagemap_cmd(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_pagemap_scan(Ptr<mm_struct> mm, @Unsigned long uarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_pages_move($arg1, $arg2, $arg3, (const void**)$arg4, (const int *)$arg5, $arg6, $arg7)")
  public static int do_pages_move(Ptr<mm_struct> mm, nodemask_t task_nodes, @Unsigned long nr_pages,
      Ptr<Ptr<?>> pages, Ptr<java.lang.Integer> nodes, Ptr<java.lang.Integer> status, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_pages_stat($arg1, $arg2, (const void**)$arg3, $arg4)")
  public static int do_pages_stat(Ptr<mm_struct> mm, @Unsigned long nr_pages, Ptr<Ptr<?>> pages,
      Ptr<java.lang.Integer> status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_pata_set_dmamode(Ptr<ata_port> ap, Ptr<ata_device> adev, int isich) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_pci_disable_device(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_pci_enable_device(Ptr<pci_dev> dev, int bars) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_aer_event($arg1, (const u8 *)$arg2, (const unsigned int)$arg3, (const u8)$arg4, (const u8)$arg5, $arg6)")
  public static void do_perf_trace_aer_event(Ptr<?> __data, String dev_name, @Unsigned int status,
      char severity, char tlp_header_valid, Ptr<pcie_tlp_log> tlp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_arm_event($arg1, (const struct cper_sec_proc_arm *)$arg2, (const u8 *)$arg3, (const unsigned int)$arg4, (const u8 *)$arg5, (const unsigned int)$arg6, (const u8 *)$arg7, (const unsigned int)$arg8, $arg9, $arg10)")
  public static void do_perf_trace_arm_event(Ptr<?> __data, Ptr<cper_sec_proc_arm> proc,
      Ptr<java.lang.Character> pei_err, @Unsigned int pei_len, Ptr<java.lang.Character> ctx_err,
      @Unsigned int ctx_len, Ptr<java.lang.Character> oem, @Unsigned int oem_len, char sev,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ata_link_reset_begin_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ata_link_reset_end_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_balance_dirty_pages(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<dirty_throttle_control> dtc, @Unsigned long dirty_ratelimit,
      @Unsigned long task_ratelimit, @Unsigned long dirtied, @Unsigned long period, long pause,
      @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_bdi_dirty_ratelimit(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned long dirty_rate, @Unsigned long task_ratelimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_block_bio(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_block_plug(Ptr<?> __data, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_block_rq(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_block_split(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned int new_sector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_bpf_trace_printk($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_bpf_trace_printk(Ptr<?> __data, String bpf_string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_bpf_xdp_link_attach_failed($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_bpf_xdp_link_attach_failed(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_br_fdb_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void do_perf_trace_br_fdb_add(Ptr<?> __data, Ptr<ndmsg> ndm, Ptr<net_device> dev,
      String addr, @Unsigned short vid, @Unsigned short nlh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_br_fdb_external_learn_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static void do_perf_trace_br_fdb_external_learn_add(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> p, String addr, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_br_fdb_update($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void do_perf_trace_br_fdb_update(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> source, String addr, @Unsigned short vid, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_br_mdb_full($arg1, (const struct net_device *)$arg2, (const struct br_ip *)$arg3)")
  public static void do_perf_trace_br_mdb_full(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<br_ip> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_cache_tag_flush(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_cache_tag_log(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_cdev_update(Ptr<?> __data, Ptr<thermal_cooling_device> cdev,
      @Unsigned long target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cgroup($arg1, $arg2, (const u8 *)$arg3)")
  public static void do_perf_trace_cgroup(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cgroup_event($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_perf_trace_cgroup_event(Ptr<?> __data, Ptr<cgroup> cgrp, String path,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cgroup_migrate($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_perf_trace_cgroup_migrate(Ptr<?> __data, Ptr<cgroup> dst_cgrp, String path,
      Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_cgroup_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_duty_cycle(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_parent(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_phase(Ptr<?> __data, Ptr<clk_core> core, int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_rate(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_rate_range(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long min, @Unsigned long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_clk_rate_request(Ptr<?> __data, Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cma_alloc_busy_retry($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6)")
  public static void do_perf_trace_cma_alloc_busy_retry(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cma_alloc_finish($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6, $arg7)")
  public static void do_perf_trace_cma_alloc_finish(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count, @Unsigned int align, int errorno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cma_alloc_start($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_cma_alloc_start(Ptr<?> __data, String name, @Unsigned long count,
      @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_cma_release($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5)")
  public static void do_perf_trace_cma_release(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_console($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_perf_trace_console(Ptr<?> __data, String text, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dax_writeback_range_class(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long start_index, @Unsigned long end_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_dev_pm_qos_request($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_dev_pm_qos_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_devfreq_frequency(Ptr<?> __data, Ptr<devfreq> devfreq,
      @Unsigned long freq, @Unsigned long prev_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_devfreq_monitor(Ptr<?> __data, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_device_pm_callback_end(Ptr<?> __data, Ptr<device> dev,
      int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_device_pm_callback_start($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_perf_trace_device_pm_callback_start(Ptr<?> __data, Ptr<device> dev,
      String pm_ops, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devlink_health_recover_aborted($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_perf_trace_devlink_health_recover_aborted(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean health_state,
      @Unsigned long time_since_last_recover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devlink_health_report($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_perf_trace_devlink_health_report(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devlink_health_reporter_state_update($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4)")
  public static void do_perf_trace_devlink_health_reporter_state_update(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devlink_hwerr($arg1, (const struct devlink *)$arg2, $arg3, (const u8 *)$arg4)")
  public static void do_perf_trace_devlink_hwerr(Ptr<?> __data, Ptr<devlink> devlink, int err,
      String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devlink_hwmsg($arg1, (const struct devlink *)$arg2, $arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void do_perf_trace_devlink_hwmsg(Ptr<?> __data, Ptr<devlink> devlink,
      boolean incoming, @Unsigned long type, Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_devres($arg1, $arg2, (const u8 *)$arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void do_perf_trace_devres(Ptr<?> __data, Ptr<device> dev, String op, Ptr<?> node,
      String name, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_alloc_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_alloc_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_fence(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_fence_unsignaled(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_free_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_free_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_map(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_map_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, int ents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_map_sg_err(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, int err, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_sync_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_sync_single(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_unmap(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dma_unmap_sg(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_dql_stall_detected(Ptr<?> __data, @Unsigned short thrs,
      @Unsigned int len, @Unsigned long last_reap, @Unsigned long hist_head, @Unsigned long now,
      Ptr<java.lang. @Unsigned Long> hist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_drm_vblank_event_queued(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_error_da_monitor_id(Ptr<?> __data, int id, String state,
      String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_event_da_monitor_id(Ptr<?> __data, int id, String state,
      String event, String next_state, boolean final_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4__bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4__es_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4__es_shrink_enter(Ptr<?> __data, Ptr<super_block> sb,
      int nr_to_scan, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_collapse_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_da_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int nr_resv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_discard_preallocations(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_drop_inode(Ptr<?> __data, Ptr<inode> inode, int drop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_lazy_itable_init(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_ext4_mb_discard_preallocations(Ptr<?> __data,
      Ptr<super_block> sb, int needed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_extlog_mem_event($arg1, $arg2, $arg3, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg4, (const u8 *)$arg5, $arg6)")
  public static void do_perf_trace_extlog_mem_event(Ptr<?> __data, Ptr<cper_sec_mem_err> mem,
      @Unsigned int err_seq, Ptr<@OriginalName("guid_t") uuid_t> fru_id, String fru_text,
      char sev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_fdb_delete(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_fdb_entry> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_fib6_table_lookup($arg1, (const struct net *)$arg2, (const struct fib6_result *)$arg3, $arg4, (const struct flowi6 *)$arg5)")
  public static void do_perf_trace_fib6_table_lookup(Ptr<?> __data, Ptr<net> net,
      Ptr<fib6_result> res, Ptr<fib6_table> table, Ptr<flowi6> flp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_fib_table_lookup($arg1, $arg2, (const struct flowi4 *)$arg3, (const struct fib_nh_common *)$arg4, $arg5)")
  public static void do_perf_trace_fib_table_lookup(Ptr<?> __data, @Unsigned int tb_id,
      Ptr<flowi4> flp, Ptr<fib_nh_common> nhc, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_flush_foreign(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned int frn_bdi_id, @Unsigned int frn_memcg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_gpio_direction(Ptr<?> __data, @Unsigned int gpio, int in,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_handshake_alert_class($arg1, (const struct sock *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_handshake_alert_class(Ptr<?> __data, Ptr<sock> sk, char level,
      char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_handshake_error_class($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void do_perf_trace_handshake_error_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_hugetlbfs_setattr(Ptr<?> __data, Ptr<inode> inode,
      Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_hwmon_attr_class($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_perf_trace_hwmon_attr_class(Ptr<?> __data, int index, String attr_name,
      long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_hwmon_attr_show_string($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_perf_trace_hwmon_attr_show_string(Ptr<?> __data, int index,
      String attr_name, String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_hyperv_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, (const struct flush_tlb_info *)$arg3)")
  public static void do_perf_trace_hyperv_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_hyperv_nested_flush_guest_mapping(Ptr<?> __data,
      @Unsigned long as, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_hyperv_send_ipi_mask($arg1, (const struct cpumask *)$arg2, $arg3)")
  public static void do_perf_trace_hyperv_send_ipi_mask(Ptr<?> __data, Ptr<cpumask> cpus,
      int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_i2c_reply($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void do_perf_trace_i2c_reply(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_i2c_slave($arg1, (const struct i2c_client *)$arg2, $arg3, $arg4, $arg5)")
  public static void do_perf_trace_i2c_slave(Ptr<?> __data, Ptr<i2c_client> client,
      i2c_slave_event event, Ptr<java.lang.Character> val, int cb_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_i2c_write($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void do_perf_trace_i2c_write(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_icc_set_bw(Ptr<?> __data, Ptr<icc_path> p, Ptr<icc_node> n,
      int i, @Unsigned int avg_bw, @Unsigned int peak_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_icc_set_bw_end(Ptr<?> __data, Ptr<icc_path> p, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_initcall_level($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_initcall_level(Ptr<?> __data, String level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_inode_foreign_history(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned int history) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_inode_switch_wbs(Ptr<?> __data, Ptr<inode> inode,
      Ptr<bdi_writeback> old_wb, Ptr<bdi_writeback> new_wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_defer(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_fail_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_poll_arm(Ptr<?> __data, Ptr<io_kiocb> req, int mask,
      int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_queue_async_work(Ptr<?> __data, Ptr<io_kiocb> req,
      int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_io_uring_req_failed($arg1, (const struct io_uring_sqe *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_io_uring_req_failed(Ptr<?> __data, Ptr<io_uring_sqe> sqe,
      Ptr<io_kiocb> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_submit_req(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_io_uring_task_add(Ptr<?> __data, Ptr<io_kiocb> req, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_iocg_inuse_update($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void do_perf_trace_iocg_inuse_update(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_iocost_ioc_vrate_adj(Ptr<?> __data, Ptr<ioc> ioc,
      @Unsigned long new_vrate, Ptr<java.lang. @Unsigned Integer> missed_ppm,
      @Unsigned int rq_wait_pct, int nr_lagging, int nr_shortages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_iocost_iocg_forgive_debt($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void do_perf_trace_iocost_iocg_forgive_debt(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned int usage_pct, @Unsigned long old_debt,
      @Unsigned long new_debt, @Unsigned long old_delay, @Unsigned long new_delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_iocost_iocg_state($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void do_perf_trace_iocost_iocg_state(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_iommu_device_event(Ptr<?> __data, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_iommu_error(Ptr<?> __data, Ptr<device> dev, @Unsigned long iova,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_iommu_group_event(Ptr<?> __data, int group_id, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_ipi_send_cpumask($arg1, (const struct cpumask *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_ipi_send_cpumask(Ptr<?> __data, Ptr<cpumask> cpumask,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_irq_handler_entry(Ptr<?> __data, int irq,
      Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_irq_noise($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_perf_trace_irq_noise(Ptr<?> __data, int vector, String desc,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_kmem_cache_free($arg1, $arg2, (const void *)$arg3, (const struct kmem_cache *)$arg4)")
  public static void do_perf_trace_kmem_cache_free(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_ma_op($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_perf_trace_ma_op(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mark_victim(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_mc_event($arg1, (const unsigned int)$arg2, (const u8 *)$arg3, (const u8 *)$arg4, (const int)$arg5, (const u8)$arg6, (const s8)$arg7, (const s8)$arg8, (const s8)$arg9, $arg10, (const u8)$arg11, $arg12, (const u8 *)$arg13)")
  public static void do_perf_trace_mc_event(Ptr<?> __data, @Unsigned int err_type, String error_msg,
      String label, int error_count, char mc_index, @OriginalName("s8") byte top_layer,
      @OriginalName("s8") byte mid_layer, @OriginalName("s8") byte low_layer,
      @Unsigned long address, char grain_bits, @Unsigned long syndrome, String driver_detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mce_record(Ptr<?> __data, Ptr<mce_hw_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mdio_access(Ptr<?> __data, Ptr<mii_bus> bus, char read,
      char addr, @Unsigned int regnum, @Unsigned short val, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mm_khugepaged_collapse_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> new_folio, @Unsigned long index, @Unsigned long addr, boolean is_shmem,
      Ptr<file> file, int nr, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mm_khugepaged_scan_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, Ptr<file> file, int present, int swap, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mm_lru_insertion(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mm_setup_per_zone_lowmem_reserve(Ptr<?> __data, Ptr<zone> zone,
      Ptr<zone> upper_zone, long lowmem_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mm_setup_per_zone_wmarks(Ptr<?> __data, Ptr<zone> zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mmc_request_done(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mmc_request_start(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_module_free(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_module_load(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_module_refcnt(Ptr<?> __data, Ptr<module> mod,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_module_request(Ptr<?> __data, String name, boolean wait,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_mptcp_subflow_get_send(Ptr<?> __data,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_napi_poll(Ptr<?> __data, Ptr<napi_struct> napi, int work,
      int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_neigh__update(Ptr<?> __data, Ptr<neighbour> n, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_neigh_create($arg1, $arg2, $arg3, (const void *)$arg4, (const struct neighbour *)$arg5, $arg6)")
  public static void do_perf_trace_neigh_create(Ptr<?> __data, Ptr<neigh_table> tbl,
      Ptr<net_device> dev, Ptr<?> pkey, Ptr<neighbour> n, boolean exempt_from_gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_neigh_update($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6)")
  public static void do_perf_trace_neigh_update(Ptr<?> __data, Ptr<neighbour> n,
      Ptr<java.lang.Character> lladdr, char _new, @Unsigned int flags, @Unsigned int nlmsg_pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_net_dev_rx_verbose_template($arg1, (const struct sk_buff *)$arg2)")
  public static void do_perf_trace_net_dev_rx_verbose_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_net_dev_start_xmit($arg1, (const struct sk_buff *)$arg2, (const struct net_device *)$arg3)")
  public static void do_perf_trace_net_dev_start_xmit(Ptr<?> __data, Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_net_dev_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_net_dev_xmit(Ptr<?> __data, Ptr<sk_buff> skb, int rc,
      Ptr<net_device> dev, @Unsigned int skb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_net_dev_xmit_timeout(Ptr<?> __data, Ptr<net_device> dev,
      int queue_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_netlink_extack($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_netlink_extack(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_non_standard_event($arg1, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg2, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg3, (const u8 *)$arg4, (const u8)$arg5, (const u8 *)$arg6, (const unsigned int)$arg7)")
  public static void do_perf_trace_non_standard_event(Ptr<?> __data,
      Ptr<@OriginalName("guid_t") uuid_t> sec_type, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev, Ptr<java.lang.Character> err, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_oom_score_adj_update(Ptr<?> __data, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_page_pool_state_release($arg1, (const struct page_pool *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_page_pool_state_release(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_percpu_create_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_prq_report(Ptr<?> __data, Ptr<intel_iommu> iommu,
      Ptr<device> dev, @Unsigned long dw0, @Unsigned long dw1, @Unsigned long dw2,
      @Unsigned long dw3, @Unsigned long seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_pseudo_lock_l2(Ptr<?> __data, @Unsigned long l2_hits,
      @Unsigned long l2_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_pwm_read_waveform(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<?> wfhw, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_qdisc_create($arg1, (const struct Qdisc_ops *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_qdisc_create(Ptr<?> __data, Ptr<Qdisc_ops> ops,
      Ptr<net_device> dev, @Unsigned int parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_qdisc_destroy(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_qdisc_reset(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_qi_submit(Ptr<?> __data, Ptr<intel_iommu> iommu,
      @Unsigned long qw0, @Unsigned long qw1, @Unsigned long qw2, @Unsigned long qw3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_regcache_drop_region(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_regcache_sync($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_perf_trace_regcache_sync(Ptr<?> __data, Ptr<regmap> map, String type,
      String status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_regmap_async(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_regmap_block(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_regmap_bool(Ptr<?> __data, Ptr<regmap> map, boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_regmap_bulk($arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static void do_perf_trace_regmap_bulk(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_regmap_reg(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_regulator_basic($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_regulator_basic(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_regulator_range($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_perf_trace_regulator_range(Ptr<?> __data, String name, int min, int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_regulator_value($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_perf_trace_regulator_value(Ptr<?> __data, String name, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_rpm_internal(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_rpm_return_int(Ptr<?> __data, Ptr<device> dev, @Unsigned long ip,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_rpm_status(Ptr<?> __data, Ptr<device> dev, rpm_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_rtc_irq_set_freq(Ptr<?> __data, int freq, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_rv_retries_error(Ptr<?> __data, String name, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_sched_ext_dump($arg1, (const u8 *)$arg2)")
  public static void do_perf_trace_sched_ext_dump(Ptr<?> __data, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_sched_ext_event($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_perf_trace_sched_ext_event(Ptr<?> __data, String name, long delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_kthread_stop(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_kthread_stop_ret(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_migrate_task(Ptr<?> __data, Ptr<task_struct> p,
      int dest_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_pi_setprio(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<task_struct> pi_task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_prepare_exec(Ptr<?> __data, Ptr<task_struct> task,
      Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_exec(Ptr<?> __data, Ptr<task_struct> p,
      @OriginalName("pid_t") int old_pid, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_exit(Ptr<?> __data, Ptr<task_struct> p,
      boolean group_dead) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_fork(Ptr<?> __data, Ptr<task_struct> parent,
      Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_hang(Ptr<?> __data, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_process_wait(Ptr<?> __data, Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_skip_cpuset_numa(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<nodemask_t> mem_allowed_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_stat_runtime(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long runtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_stat_template(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_switch(Ptr<?> __data, boolean preempt,
      Ptr<task_struct> prev, Ptr<task_struct> next, @Unsigned int prev_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sched_wakeup_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_scsi_cmd_done_timeout_template(Ptr<?> __data,
      Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_scsi_dispatch_cmd_error(Ptr<?> __data, Ptr<scsi_cmnd> cmd,
      int rtn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_scsi_dispatch_cmd_start(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_selinux_audited($arg1, $arg2, $arg3, $arg4, (const u8 *)$arg5)")
  public static void do_perf_trace_selinux_audited(Ptr<?> __data, Ptr<selinux_audit_data> sad,
      String scontext, String tcontext, String tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_signal_generate(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<task_struct> task, int group, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sock_exceed_buf_limit(Ptr<?> __data, Ptr<sock> sk,
      Ptr<proto> prot, long allocated, int kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_spi_transfer(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_swiotlb_bounced(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dev_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_sync_timeline(Ptr<?> __data, Ptr<sync_timeline> timeline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_task_newtask(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_task_rename($arg1, $arg2, (const u8 *)$arg3)")
  public static void do_perf_trace_task_rename(Ptr<?> __data, Ptr<task_struct> task, String comm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_ao_event($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void do_perf_trace_tcp_ao_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_ao_event_sk($arg1, (const struct sock *)$arg2, (const u8)$arg3, (const u8)$arg4)")
  public static void do_perf_trace_tcp_ao_event_sk(Ptr<?> __data, Ptr<sock> sk, char keyid,
      char rnext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_ao_event_sne($arg1, (const struct sock *)$arg2, $arg3)")
  public static void do_perf_trace_tcp_ao_event_sne(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_event_skb($arg1, (const struct sk_buff *)$arg2)")
  public static void do_perf_trace_tcp_event_skb(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_hash_event($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void do_perf_trace_tcp_hash_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_probe($arg1, $arg2, (const struct sk_buff *)$arg3)")
  public static void do_perf_trace_tcp_probe(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_tcp_rcvbuf_grow(Ptr<?> __data, Ptr<sock> sk, int time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tcp_send_reset($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const enum sk_rst_reason)$arg4)")
  public static void do_perf_trace_tcp_send_reset(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb__nullable, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_thermal_power_devfreq_get_power(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, Ptr<devfreq_dev_status> status, @Unsigned long freq,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_thermal_power_devfreq_limit(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long freq, @Unsigned long cdev_state,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_thermal_temperature(Ptr<?> __data, Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_thermal_zone_trip(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int trip, thermal_trip_type trip_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_thread_noise(Ptr<?> __data, Ptr<task_struct> t,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_timer_class(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tls_contenttype($arg1, (const struct sock *)$arg2, $arg3)")
  public static void do_perf_trace_tls_contenttype(Ptr<?> __data, Ptr<sock> sk, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_track_foreign_dirty(Ptr<?> __data, Ptr<folio> folio,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tsm_mr_read($arg1, (const struct tsm_measurement_register *)$arg2)")
  public static void do_perf_trace_tsm_mr_read(Ptr<?> __data, Ptr<tsm_measurement_register> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tsm_mr_refresh($arg1, (const struct tsm_measurement_register *)$arg2, $arg3)")
  public static void do_perf_trace_tsm_mr_refresh(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_tsm_mr_write($arg1, (const struct tsm_measurement_register *)$arg2, (const u8 *)$arg3)")
  public static void do_perf_trace_tsm_mr_write(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_udp_fail_queue_rcv_skb(Ptr<?> __data, int rc, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_wake_reaper(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_wakeup_source($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_perf_trace_wakeup_source(Ptr<?> __data, String name, @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_wbc_class(Ptr<?> __data, Ptr<writeback_control> wbc,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_wbt_lat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned long lat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_wbt_stat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_wbt_step($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void do_perf_trace_wbt_step(Ptr<?> __data, Ptr<backing_dev_info> bdi, String msg,
      int step, @Unsigned long window, @Unsigned int bg, @Unsigned int normal, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_wbt_timer(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned int status, int step, @Unsigned int inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_workqueue_activate_work(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_workqueue_queue_work(Ptr<?> __data, int req_cpu,
      Ptr<pool_workqueue> pwq, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_bdi_register(Ptr<?> __data,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_class(Ptr<?> __data, Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_dirty_inode_template(Ptr<?> __data, Ptr<inode> inode,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_folio_template(Ptr<?> __data, Ptr<folio> folio,
      Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_queue_io(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work, @Unsigned long dirtied_before, int moved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_sb_inodes_requeue(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_single_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_work_class(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_writeback_write_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xen_mc__batch(Ptr<?> __data, xen_lazy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xen_mc_entry(Ptr<?> __data, Ptr<multicall_entry> mc,
      @Unsigned int nargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xen_mc_entry_alloc(Ptr<?> __data, @Unsigned long args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_perf_trace_xen_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, $arg3, $arg4, $arg5)")
  public static void do_perf_trace_xen_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<mm_struct> mm, @Unsigned long addr, @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xhci_log_ctx(Ptr<?> __data, Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx, @Unsigned int ep_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xhci_log_msg(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_perf_trace_xhci_log_urb(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_perms(Ptr<aa_profile> profile, @Unsigned int state, @Unsigned int request,
      Ptr<aa_perms> p, Ptr<apparmor_audit_data> ad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_pidfd_send_signal(Ptr<pid> pid, int sig, pid_type type,
      Ptr<@OriginalName("siginfo_t") siginfo> info, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_pipe2(Ptr<java.lang.Integer> fildes, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_pipe_flags(Ptr<java.lang.Integer> fd, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_ploaddata_rmfs(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_poll(Ptr<poll_list> list, Ptr<poll_wqueues> wait, Ptr<timespec64> end_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_populate_rootfs(Ptr<?> unused,
      @Unsigned @OriginalName("async_cookie_t") long cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_preadv($arg1, (const struct iovec *)$arg2, $arg3, $arg4, $arg5)")
  public static @OriginalName("ssize_t") long do_preadv(@Unsigned long fd, Ptr<iovec> vec,
      @Unsigned long vlen, @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_prlimit(Ptr<task_struct> tsk, @Unsigned int resource, Ptr<rlimit> new_rlim,
      Ptr<rlimit> old_rlim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_bulk(Ptr<usb_dev_state> ps, Ptr<usbdevfs_bulktransfer> bulk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_control(Ptr<usb_dev_state> ps, Ptr<usbdevfs_ctrltransfer> ctrl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_conv(Ptr<java.lang. @OriginalName("bool") Boolean> negp,
      Ptr<java.lang. @Unsigned Long> lvalp, Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_jiffies_conv(
      Ptr<java.lang. @OriginalName("bool") Boolean> negp, Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_minmax_conv(Ptr<java.lang. @OriginalName("bool") Boolean> negp,
      Ptr<java.lang. @Unsigned Long> lvalp, Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_ms_jiffies_conv(
      Ptr<java.lang. @OriginalName("bool") Boolean> negp, Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_ms_jiffies_minmax_conv(
      Ptr<java.lang. @OriginalName("bool") Boolean> negp, Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dointvec_userhz_jiffies_conv(
      Ptr<java.lang. @OriginalName("bool") Boolean> negp, Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang.Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_dopipe_max_size_conv(Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang. @Unsigned Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_proc_douintvec((const struct ctl_table *)$arg1, $arg2, $arg3, $arg4, $arg5, (int (*)(long unsigned int*, unsigned int*, int, void*))$arg6, $arg7)")
  public static int do_proc_douintvec(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos,
      Ptr<?> conv, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_douintvec_conv(Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang. @Unsigned Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_proc_douintvec_minmax_conv(Ptr<java.lang. @Unsigned Long> lvalp,
      Ptr<java.lang. @Unsigned Integer> valp, int write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_proc_dqstats((const struct ctl_table *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int do_proc_dqstats(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_procmap_query(Ptr<proc_maps_private> priv, Ptr<?> uarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_prt_fixups(Ptr<acpi_prt_entry> entry, Ptr<acpi_pci_routing_table> prt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_pselect($arg1, $arg2, $arg3, $arg4, $arg5, (const struct {\n"
          + "  long unsigned int sig[1];\n"
          + "} *)$arg6, $arg7, $arg8)")
  public static long do_pselect(int n, Ptr<@OriginalName("fd_set") __kernel_fd_set> inp,
      Ptr<@OriginalName("fd_set") __kernel_fd_set> outp,
      Ptr<@OriginalName("fd_set") __kernel_fd_set> exp, Ptr<?> tsp, Ptr<sigset_t> sigmask,
      @Unsigned long sigsetsize, poll_time_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_pwritev($arg1, (const struct iovec *)$arg2, $arg3, $arg4, $arg5)")
  public static @OriginalName("ssize_t") long do_pwritev(@Unsigned long fd, Ptr<iovec> vec,
      @Unsigned long vlen, @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_quotactl($arg1, $arg2, $arg3, $arg4, $arg5, (const struct path *)$arg6)")
  public static int do_quotactl(Ptr<super_block> sb, int type, int cmd,
      @Unsigned @OriginalName("qid_t") int id, Ptr<?> addr, Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<folio> do_read_cache_folio(Ptr<address_space> mapping, @Unsigned long index,
      Ptr<?> filler, Ptr<file> file, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_read_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_readahead(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_readlinkat($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int do_readlinkat(int dfd, String pathname, String buf, int bufsiz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_readv($arg1, (const struct iovec *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long do_readv(@Unsigned long fd, Ptr<iovec> vec,
      @Unsigned long vlen, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_reboot() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_recvmmsg(int fd, Ptr<mmsghdr> mmsg, @Unsigned int vlen, @Unsigned int flags,
      Ptr<timespec64> timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_region((const unsigned int)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void do_region(@Unsigned @OriginalName("blk_opf_t") int opf, @Unsigned int region,
      Ptr<dm_io_region> where, Ptr<dpages> dp, Ptr<io> io, @Unsigned short ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_register_con_driver((const struct consw *)$arg1, $arg2, $arg3)")
  public static int do_register_con_driver(Ptr<consw> csw, int first, int last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_register_framebuffer(Ptr<fb_info> fb_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_register_memory_block_under_node(int nid, Ptr<memory_block> mem_blk,
      meminit_context context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_renameat2(int olddfd, Ptr<filename> from, int newdfd, Ptr<filename> to,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_reset() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_restart_poll(Ptr<restart_block> restart_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_resume(Ptr<dm_ioctl> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_rmdir(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_rt_sigqueueinfo(@OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_rt_tgsigqueueinfo(@OriginalName("pid_t") int tgid,
      @OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_scan_async(Ptr<?> _data, @Unsigned @OriginalName("async_cookie_t") long c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sched_setscheduler(@OriginalName("pid_t") int pid, int policy,
      Ptr<sched_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sched_yield() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_scsi_scan_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_seccomp(@Unsigned int op, @Unsigned int flags, Ptr<?> uargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_select(int n, Ptr<fd_set_bits> fds, Ptr<timespec64> end_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_semtimedop($arg1, $arg2, $arg3, (const struct timespec64 *)$arg4)")
  public static long do_semtimedop(int semid, Ptr<sembuf> tsops, @Unsigned int nsops,
      Ptr<timespec64> timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_send_sig_info(int sig, Ptr<kernel_siginfo> info, Ptr<task_struct> p,
      pid_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_send_specific(@OriginalName("pid_t") int tgid,
      @OriginalName("pid_t") int pid, int sig, Ptr<kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_sendfile(int out_fd, int in_fd,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long count,
      @OriginalName("loff_t") long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_set_acl($arg1, $arg2, (const u8 *)$arg3, (const void *)$arg4, $arg5)")
  public static int do_set_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, String acl_name,
      Ptr<?> kvalue, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_set_cpus_allowed($arg1, (const struct cpumask *)$arg2)")
  public static void do_set_cpus_allowed(Ptr<task_struct> p, Ptr<cpumask> new_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_set_dqblk(Ptr<dquot> dquot, Ptr<qc_dqblk> di) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_set_group(Ptr<path> from_path, Ptr<path> to_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_set_master(Ptr<net_device> dev, int ifindex, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_set_mempolicy(@Unsigned short mode, @Unsigned short flags,
      Ptr<nodemask_t> nodes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_set_pmd(Ptr<vm_fault> vmf,
      Ptr<folio> folio, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_set_thread_area(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int can_allocate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_setitimer(int which, Ptr<itimerspec64> value, Ptr<itimerspec64> ovalue) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_settimeofday64((const struct timespec64 *)$arg1)")
  public static int do_settimeofday64(Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_setvfinfo(Ptr<net_device> dev, Ptr<Ptr<nlattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_setxattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      Ptr<kernel_xattr_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_shared_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_shm_rmid(Ptr<ipc_namespace> ns, Ptr<kern_ipc_perm> ipcp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_shmat(int shmid, String shmaddr, int shmflg,
      Ptr<java.lang. @Unsigned @OriginalName("ulong") Long> raddr, @Unsigned long shmlba) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long do_shrink_slab(Ptr<shrink_control> shrinkctl, Ptr<shrinker> shrinker,
      int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sigaction(int sig, Ptr<k_sigaction> act, Ptr<k_sigaction> oact) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sigaltstack((const sigaltstack *)$arg1, $arg2, $arg3, $arg4)")
  public static int do_sigaltstack(Ptr<@OriginalName("stack_t") sigaltstack> ss,
      Ptr<@OriginalName("stack_t") sigaltstack> oss, @Unsigned long sp,
      @Unsigned long min_ss_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_signal_stop(int signr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_signalfd4(int ufd, Ptr<sigset_t> mask, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_skip() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_smart_update(Ptr<sem_array> sma, Ptr<sembuf> sops, int nsops, int otime,
      Ptr<wake_q_head> wake_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_smart_wakeup_zero(Ptr<sem_array> sma, Ptr<sembuf> sops, int nsops,
      Ptr<wake_q_head> wake_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sock_getsockopt(Ptr<socket> sock, boolean compat, int level, int optname,
      sockptr_t optval, sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sock_setsockopt(Ptr<socket> sock, boolean compat, int level, int optname,
      sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_softirq() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_splice(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_in, Ptr<file> out,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_splice_direct(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<file> out,
      Ptr<java.lang. @OriginalName("loff_t") Long> opos, @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_splice_read(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_dir_entry_2> do_split(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> dir,
      Ptr<Ptr<buffer_head>> bh, Ptr<dx_frame> frame, Ptr<dx_hash_info> hinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_spring_cleaning(Ptr<ce_array> ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sta_before_sun((const struct dmi_system_id *)$arg1)")
  public static int do_sta_before_sun(Ptr<dmi_system_id> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_standard_modes((const struct detailed_timing *)$arg1, $arg2)")
  public static void do_standard_modes(Ptr<detailed_timing> timing, Ptr<?> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_start() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_statfs64(Ptr<kstatfs> st, Ptr<statfs64> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_statfs_native(Ptr<kstatfs> st, Ptr<statfs> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_statmount(Ptr<kstatmount> s, @Unsigned long mnt_id, @Unsigned long mnt_ns_id,
      Ptr<mnt_namespace> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_statx(int dfd, Ptr<filename> filename, @Unsigned int flags,
      @Unsigned int mask, Ptr<statx> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_statx_fd(int fd, @Unsigned int flags, @Unsigned int mask,
      Ptr<statx> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_suspend_lowlevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_swap_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_symlink() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_symlinkat(Ptr<filename> from, int newdfd, Ptr<filename> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sync_core(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> do_sync_mmap_readahead(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sync_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sys_ftruncate(@Unsigned int fd, @OriginalName("loff_t") long length,
      int small) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sys_name_to_handle((const struct path *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static long do_sys_name_to_handle(Ptr<path> path, Ptr<file_handle> ufh, Ptr<?> mnt_id,
      boolean unique_mntid, int fh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sys_open($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int do_sys_open(int dfd, String filename, int flags,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sys_openat2($arg1, (const u8 *)$arg2, $arg3)")
  public static int do_sys_openat2(int dfd, String filename, Ptr<open_how> how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sys_poll(Ptr<pollfd> ufds, @Unsigned int nfds, Ptr<timespec64> end_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sys_settimeofday64((const struct timespec64 *)$arg1, (const struct timezone *)$arg2)")
  public static int do_sys_settimeofday64(Ptr<timespec64> tv, Ptr<timezone> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sys_times(Ptr<tms> tms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_sys_truncate((const u8 *)$arg1, $arg2)")
  public static int do_sys_truncate(String pathname, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean do_syscall_64(Ptr<pt_regs> regs, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sysctl_args() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_sysfs_unregistration() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_sysinfo(Ptr<sysinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_syslog(int type, String buf, int len, int source) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_take_over_console((const struct consw *)$arg1, $arg2, $arg3, $arg4)")
  public static int do_take_over_console(Ptr<consw> csw, int first, int last, int deflt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_task_dead() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_task_stat(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task, int whole) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_tcp_getsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_tcp_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long do_tee(Ptr<file> in, Ptr<file> out,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_thaw_all(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_thaw_all_callback(Ptr<super_block> sb, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ktime_t") long do_timens_ktime_to_host(
      @OriginalName("clockid_t") int clockid, @OriginalName("ktime_t") long tim,
      Ptr<timens_offsets> ns_offsets) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_timer(@Unsigned long ticks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_timer_create(@OriginalName("clockid_t") int which_clock, Ptr<sigevent> event,
      Ptr<java.lang. @OriginalName("timer_t") Integer> created_timer_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_timer_gettime(@OriginalName("timer_t") int timer_id,
      Ptr<itimerspec64> setting) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_timer_settime(@OriginalName("timer_t") int timer_id, int tmr_flags,
      Ptr<itimerspec64> new_spec64, Ptr<itimerspec64> old_spec64) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_timerfd_gettime(int ufd, Ptr<itimerspec64> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_timerfd_settime($arg1, $arg2, (const struct itimerspec64 *)$arg3, $arg4)")
  public static int do_timerfd_settime(int ufd, int flags, Ptr<itimerspec64> _new,
      Ptr<itimerspec64> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_aer_event($arg1, (const u8 *)$arg2, (const unsigned int)$arg3, (const u8)$arg4, (const u8)$arg5, $arg6)")
  public static void do_trace_event_raw_event_aer_event(Ptr<?> __data, String dev_name,
      @Unsigned int status, char severity, char tlp_header_valid, Ptr<pcie_tlp_log> tlp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_arm_event($arg1, (const struct cper_sec_proc_arm *)$arg2, (const u8 *)$arg3, (const unsigned int)$arg4, (const u8 *)$arg5, (const unsigned int)$arg6, (const u8 *)$arg7, (const unsigned int)$arg8, $arg9, $arg10)")
  public static void do_trace_event_raw_event_arm_event(Ptr<?> __data, Ptr<cper_sec_proc_arm> proc,
      Ptr<java.lang.Character> pei_err, @Unsigned int pei_len, Ptr<java.lang.Character> ctx_err,
      @Unsigned int ctx_len, Ptr<java.lang.Character> oem, @Unsigned int oem_len, char sev,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_ata_link_reset_begin_template(Ptr<?> __data,
      Ptr<ata_link> link, Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_ata_link_reset_end_template(Ptr<?> __data,
      Ptr<ata_link> link, Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_balance_dirty_pages(Ptr<?> __data,
      Ptr<bdi_writeback> wb, Ptr<dirty_throttle_control> dtc, @Unsigned long dirty_ratelimit,
      @Unsigned long task_ratelimit, @Unsigned long dirtied, @Unsigned long period, long pause,
      @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_bdi_dirty_ratelimit(Ptr<?> __data,
      Ptr<bdi_writeback> wb, @Unsigned long dirty_rate, @Unsigned long task_ratelimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_block_bio(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_block_plug(Ptr<?> __data, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_block_rq(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_block_split(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned int new_sector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_bpf_trace_printk($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_bpf_trace_printk(Ptr<?> __data, String bpf_string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_bpf_xdp_link_attach_failed($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_bpf_xdp_link_attach_failed(Ptr<?> __data,
      String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_br_fdb_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void do_trace_event_raw_event_br_fdb_add(Ptr<?> __data, Ptr<ndmsg> ndm,
      Ptr<net_device> dev, String addr, @Unsigned short vid, @Unsigned short nlh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_br_fdb_external_learn_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static void do_trace_event_raw_event_br_fdb_external_learn_add(Ptr<?> __data,
      Ptr<net_bridge> br, Ptr<net_bridge_port> p, String addr, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_br_fdb_update($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void do_trace_event_raw_event_br_fdb_update(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> source, String addr, @Unsigned short vid, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_br_mdb_full($arg1, (const struct net_device *)$arg2, (const struct br_ip *)$arg3)")
  public static void do_trace_event_raw_event_br_mdb_full(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<br_ip> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_cache_tag_flush(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_cache_tag_log(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_cdev_update(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cgroup($arg1, $arg2, (const u8 *)$arg3)")
  public static void do_trace_event_raw_event_cgroup(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cgroup_event($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_cgroup_event(Ptr<?> __data, Ptr<cgroup> cgrp,
      String path, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cgroup_migrate($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_trace_event_raw_event_cgroup_migrate(Ptr<?> __data, Ptr<cgroup> dst_cgrp,
      String path, Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_cgroup_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_duty_cycle(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_parent(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_phase(Ptr<?> __data, Ptr<clk_core> core,
      int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_rate(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_rate_range(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long min, @Unsigned long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_clk_rate_request(Ptr<?> __data,
      Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cma_alloc_busy_retry($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6)")
  public static void do_trace_event_raw_event_cma_alloc_busy_retry(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cma_alloc_finish($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6, $arg7)")
  public static void do_trace_event_raw_event_cma_alloc_finish(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count, @Unsigned int align, int errorno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cma_alloc_start($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_cma_alloc_start(Ptr<?> __data, String name,
      @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_cma_release($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5)")
  public static void do_trace_event_raw_event_cma_release(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_console($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_console(Ptr<?> __data, String text,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_dev_pm_qos_request($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_dev_pm_qos_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_devfreq_frequency(Ptr<?> __data, Ptr<devfreq> devfreq,
      @Unsigned long freq, @Unsigned long prev_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_devfreq_monitor(Ptr<?> __data, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_device_pm_callback_end(Ptr<?> __data, Ptr<device> dev,
      int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_device_pm_callback_start($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_device_pm_callback_start(Ptr<?> __data,
      Ptr<device> dev, String pm_ops, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devlink_health_recover_aborted($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_trace_event_raw_event_devlink_health_recover_aborted(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean health_state,
      @Unsigned long time_since_last_recover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devlink_health_report($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_trace_event_raw_event_devlink_health_report(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devlink_health_reporter_state_update($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_devlink_health_reporter_state_update(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devlink_hwerr($arg1, (const struct devlink *)$arg2, $arg3, (const u8 *)$arg4)")
  public static void do_trace_event_raw_event_devlink_hwerr(Ptr<?> __data, Ptr<devlink> devlink,
      int err, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devlink_hwmsg($arg1, (const struct devlink *)$arg2, $arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void do_trace_event_raw_event_devlink_hwmsg(Ptr<?> __data, Ptr<devlink> devlink,
      boolean incoming, @Unsigned long type, Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_devres($arg1, $arg2, (const u8 *)$arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void do_trace_event_raw_event_devres(Ptr<?> __data, Ptr<device> dev, String op,
      Ptr<?> node, String name, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_alloc_class(Ptr<?> __data, Ptr<device> dev,
      Ptr<?> virt_addr, @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_alloc_sgt(Ptr<?> __data, Ptr<device> dev,
      Ptr<sg_table> sgt, @Unsigned long size, dma_data_direction dir,
      @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_fence(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_fence_unsignaled(Ptr<?> __data,
      Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_free_class(Ptr<?> __data, Ptr<device> dev,
      Ptr<?> virt_addr, @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_free_sgt(Ptr<?> __data, Ptr<device> dev,
      Ptr<sg_table> sgt, @Unsigned long size, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_map(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_map_sg(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, int ents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_map_sg_err(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, int err, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_sync_sg(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_sync_single(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_unmap(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dma_unmap_sg(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_dql_stall_detected(Ptr<?> __data,
      @Unsigned short thrs, @Unsigned int len, @Unsigned long last_reap, @Unsigned long hist_head,
      @Unsigned long now, Ptr<java.lang. @Unsigned Long> hist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_error_da_monitor_id(Ptr<?> __data, int id,
      String state, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_event_da_monitor_id(Ptr<?> __data, int id,
      String state, String event, String next_state, boolean final_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_ext4__es_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_extlog_mem_event($arg1, $arg2, $arg3, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg4, (const u8 *)$arg5, $arg6)")
  public static void do_trace_event_raw_event_extlog_mem_event(Ptr<?> __data,
      Ptr<cper_sec_mem_err> mem, @Unsigned int err_seq, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_fdb_delete(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_fdb_entry> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_fib6_table_lookup($arg1, (const struct net *)$arg2, (const struct fib6_result *)$arg3, $arg4, (const struct flowi6 *)$arg5)")
  public static void do_trace_event_raw_event_fib6_table_lookup(Ptr<?> __data, Ptr<net> net,
      Ptr<fib6_result> res, Ptr<fib6_table> table, Ptr<flowi6> flp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_fib_table_lookup($arg1, $arg2, (const struct flowi4 *)$arg3, (const struct fib_nh_common *)$arg4, $arg5)")
  public static void do_trace_event_raw_event_fib_table_lookup(Ptr<?> __data, @Unsigned int tb_id,
      Ptr<flowi4> flp, Ptr<fib_nh_common> nhc, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_flush_foreign(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned int frn_bdi_id, @Unsigned int frn_memcg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_handshake_alert_class($arg1, (const struct sock *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_handshake_alert_class(Ptr<?> __data, Ptr<sock> sk,
      char level, char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_hugetlbfs_setattr(Ptr<?> __data, Ptr<inode> inode,
      Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_hwmon_attr_class($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_hwmon_attr_class(Ptr<?> __data, int index,
      String attr_name, long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_hwmon_attr_show_string($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_trace_event_raw_event_hwmon_attr_show_string(Ptr<?> __data, int index,
      String attr_name, String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_hyperv_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, (const struct flush_tlb_info *)$arg3)")
  public static void do_trace_event_raw_event_hyperv_mmu_flush_tlb_multi(Ptr<?> __data,
      Ptr<cpumask> cpus, Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_hyperv_send_ipi_mask($arg1, (const struct cpumask *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_hyperv_send_ipi_mask(Ptr<?> __data, Ptr<cpumask> cpus,
      int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_i2c_reply($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_i2c_reply(Ptr<?> __data, Ptr<i2c_adapter> adap,
      Ptr<i2c_msg> msg, int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_i2c_slave($arg1, (const struct i2c_client *)$arg2, $arg3, $arg4, $arg5)")
  public static void do_trace_event_raw_event_i2c_slave(Ptr<?> __data, Ptr<i2c_client> client,
      i2c_slave_event event, Ptr<java.lang.Character> val, int cb_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_i2c_write($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void do_trace_event_raw_event_i2c_write(Ptr<?> __data, Ptr<i2c_adapter> adap,
      Ptr<i2c_msg> msg, int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_icc_set_bw(Ptr<?> __data, Ptr<icc_path> p,
      Ptr<icc_node> n, int i, @Unsigned int avg_bw, @Unsigned int peak_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_icc_set_bw_end(Ptr<?> __data, Ptr<icc_path> p,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_initcall_level($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_initcall_level(Ptr<?> __data, String level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_inode_foreign_history(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned int history) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_inode_switch_wbs(Ptr<?> __data, Ptr<inode> inode,
      Ptr<bdi_writeback> old_wb, Ptr<bdi_writeback> new_wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_defer(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_fail_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_poll_arm(Ptr<?> __data, Ptr<io_kiocb> req,
      int mask, int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_queue_async_work(Ptr<?> __data,
      Ptr<io_kiocb> req, int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_io_uring_req_failed($arg1, (const struct io_uring_sqe *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_io_uring_req_failed(Ptr<?> __data,
      Ptr<io_uring_sqe> sqe, Ptr<io_kiocb> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_submit_req(Ptr<?> __data,
      Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_io_uring_task_add(Ptr<?> __data, Ptr<io_kiocb> req,
      int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_iocg_inuse_update($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void do_trace_event_raw_event_iocg_inuse_update(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_iocost_ioc_vrate_adj(Ptr<?> __data, Ptr<ioc> ioc,
      @Unsigned long new_vrate, Ptr<java.lang. @Unsigned Integer> missed_ppm,
      @Unsigned int rq_wait_pct, int nr_lagging, int nr_shortages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_iocost_iocg_forgive_debt($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void do_trace_event_raw_event_iocost_iocg_forgive_debt(Ptr<?> __data,
      Ptr<ioc_gq> iocg, String path, Ptr<ioc_now> now, @Unsigned int usage_pct,
      @Unsigned long old_debt, @Unsigned long new_debt, @Unsigned long old_delay,
      @Unsigned long new_delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_iocost_iocg_state($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void do_trace_event_raw_event_iocost_iocg_state(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_iommu_device_event(Ptr<?> __data, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_iommu_error(Ptr<?> __data, Ptr<device> dev,
      @Unsigned long iova, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_iommu_group_event(Ptr<?> __data, int group_id,
      Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_ipi_send_cpumask($arg1, (const struct cpumask *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_ipi_send_cpumask(Ptr<?> __data, Ptr<cpumask> cpumask,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_irq_handler_entry(Ptr<?> __data, int irq,
      Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_irq_noise($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void do_trace_event_raw_event_irq_noise(Ptr<?> __data, int vector, String desc,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_kmem_cache_free($arg1, $arg2, (const void *)$arg3, (const struct kmem_cache *)$arg4)")
  public static void do_trace_event_raw_event_kmem_cache_free(Ptr<?> __data,
      @Unsigned long call_site, Ptr<?> ptr, Ptr<kmem_cache> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mark_victim(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_mc_event($arg1, (const unsigned int)$arg2, (const u8 *)$arg3, (const u8 *)$arg4, (const int)$arg5, (const u8)$arg6, (const s8)$arg7, (const s8)$arg8, (const s8)$arg9, $arg10, (const u8)$arg11, $arg12, (const u8 *)$arg13)")
  public static void do_trace_event_raw_event_mc_event(Ptr<?> __data, @Unsigned int err_type,
      String error_msg, String label, int error_count, char mc_index,
      @OriginalName("s8") byte top_layer, @OriginalName("s8") byte mid_layer,
      @OriginalName("s8") byte low_layer, @Unsigned long address, char grain_bits,
      @Unsigned long syndrome, String driver_detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mce_record(Ptr<?> __data, Ptr<mce_hw_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mdio_access(Ptr<?> __data, Ptr<mii_bus> bus,
      char read, char addr, @Unsigned int regnum, @Unsigned short val, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mm_khugepaged_collapse_file(Ptr<?> __data,
      Ptr<mm_struct> mm, Ptr<folio> new_folio, @Unsigned long index, @Unsigned long addr,
      boolean is_shmem, Ptr<file> file, int nr, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mm_khugepaged_scan_file(Ptr<?> __data,
      Ptr<mm_struct> mm, Ptr<folio> folio, Ptr<file> file, int present, int swap, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mm_setup_per_zone_lowmem_reserve(Ptr<?> __data,
      Ptr<zone> zone, Ptr<zone> upper_zone, long lowmem_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mm_setup_per_zone_wmarks(Ptr<?> __data,
      Ptr<zone> zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mmc_request_done(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mmc_request_start(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_module_free(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_module_load(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_module_refcnt(Ptr<?> __data, Ptr<module> mod,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_module_request(Ptr<?> __data, String name,
      boolean wait, @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_mptcp_subflow_get_send(Ptr<?> __data,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_napi_poll(Ptr<?> __data, Ptr<napi_struct> napi,
      int work, int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_neigh__update(Ptr<?> __data, Ptr<neighbour> n,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_neigh_create($arg1, $arg2, $arg3, (const void *)$arg4, (const struct neighbour *)$arg5, $arg6)")
  public static void do_trace_event_raw_event_neigh_create(Ptr<?> __data, Ptr<neigh_table> tbl,
      Ptr<net_device> dev, Ptr<?> pkey, Ptr<neighbour> n, boolean exempt_from_gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_neigh_update($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6)")
  public static void do_trace_event_raw_event_neigh_update(Ptr<?> __data, Ptr<neighbour> n,
      Ptr<java.lang.Character> lladdr, char _new, @Unsigned int flags, @Unsigned int nlmsg_pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_net_dev_rx_verbose_template($arg1, (const struct sk_buff *)$arg2)")
  public static void do_trace_event_raw_event_net_dev_rx_verbose_template(Ptr<?> __data,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_net_dev_start_xmit($arg1, (const struct sk_buff *)$arg2, (const struct net_device *)$arg3)")
  public static void do_trace_event_raw_event_net_dev_start_xmit(Ptr<?> __data, Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_net_dev_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_net_dev_xmit(Ptr<?> __data, Ptr<sk_buff> skb, int rc,
      Ptr<net_device> dev, @Unsigned int skb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_net_dev_xmit_timeout(Ptr<?> __data,
      Ptr<net_device> dev, int queue_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_netlink_extack($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_netlink_extack(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_non_standard_event($arg1, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg2, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg3, (const u8 *)$arg4, (const u8)$arg5, (const u8 *)$arg6, (const unsigned int)$arg7)")
  public static void do_trace_event_raw_event_non_standard_event(Ptr<?> __data,
      Ptr<@OriginalName("guid_t") uuid_t> sec_type, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev, Ptr<java.lang.Character> err, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_oom_score_adj_update(Ptr<?> __data,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_page_pool_state_release($arg1, (const struct page_pool *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_page_pool_state_release(Ptr<?> __data,
      Ptr<page_pool> pool, @Unsigned @OriginalName("netmem_ref") long netmem,
      @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_prq_report(Ptr<?> __data, Ptr<intel_iommu> iommu,
      Ptr<device> dev, @Unsigned long dw0, @Unsigned long dw1, @Unsigned long dw2,
      @Unsigned long dw3, @Unsigned long seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_qdisc_create($arg1, (const struct Qdisc_ops *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_qdisc_create(Ptr<?> __data, Ptr<Qdisc_ops> ops,
      Ptr<net_device> dev, @Unsigned int parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_qdisc_destroy(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_qdisc_reset(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_qi_submit(Ptr<?> __data, Ptr<intel_iommu> iommu,
      @Unsigned long qw0, @Unsigned long qw1, @Unsigned long qw2, @Unsigned long qw3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_regcache_drop_region(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_regcache_sync($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void do_trace_event_raw_event_regcache_sync(Ptr<?> __data, Ptr<regmap> map,
      String type, String status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_regmap_async(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_regmap_block(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_regmap_bool(Ptr<?> __data, Ptr<regmap> map,
      boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_regmap_bulk($arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static void do_trace_event_raw_event_regmap_bulk(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_regmap_reg(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_regulator_basic($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_regulator_basic(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_regulator_range($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void do_trace_event_raw_event_regulator_range(Ptr<?> __data, String name, int min,
      int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_regulator_value($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_regulator_value(Ptr<?> __data, String name,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_rpm_internal(Ptr<?> __data, Ptr<device> dev,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_rpm_return_int(Ptr<?> __data, Ptr<device> dev,
      @Unsigned long ip, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_rpm_status(Ptr<?> __data, Ptr<device> dev,
      rpm_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_rv_retries_error(Ptr<?> __data, String name,
      String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_sched_ext_dump($arg1, (const u8 *)$arg2)")
  public static void do_trace_event_raw_event_sched_ext_dump(Ptr<?> __data, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_sched_ext_event($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_sched_ext_event(Ptr<?> __data, String name,
      long delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_kthread_stop(Ptr<?> __data,
      Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_migrate_task(Ptr<?> __data, Ptr<task_struct> p,
      int dest_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_pi_setprio(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<task_struct> pi_task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_prepare_exec(Ptr<?> __data,
      Ptr<task_struct> task, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_exec(Ptr<?> __data, Ptr<task_struct> p,
      @OriginalName("pid_t") int old_pid, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_exit(Ptr<?> __data, Ptr<task_struct> p,
      boolean group_dead) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_fork(Ptr<?> __data,
      Ptr<task_struct> parent, Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_hang(Ptr<?> __data,
      Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_template(Ptr<?> __data,
      Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_process_wait(Ptr<?> __data, Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_skip_cpuset_numa(Ptr<?> __data,
      Ptr<task_struct> tsk, Ptr<nodemask_t> mem_allowed_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_stat_runtime(Ptr<?> __data,
      Ptr<task_struct> tsk, @Unsigned long runtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_stat_template(Ptr<?> __data,
      Ptr<task_struct> tsk, @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_switch(Ptr<?> __data, boolean preempt,
      Ptr<task_struct> prev, Ptr<task_struct> next, @Unsigned int prev_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sched_wakeup_template(Ptr<?> __data,
      Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_scsi_cmd_done_timeout_template(Ptr<?> __data,
      Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_scsi_dispatch_cmd_error(Ptr<?> __data,
      Ptr<scsi_cmnd> cmd, int rtn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_scsi_dispatch_cmd_start(Ptr<?> __data,
      Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_selinux_audited($arg1, $arg2, $arg3, $arg4, (const u8 *)$arg5)")
  public static void do_trace_event_raw_event_selinux_audited(Ptr<?> __data,
      Ptr<selinux_audit_data> sad, String scontext, String tcontext, String tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_signal_generate(Ptr<?> __data, int sig,
      Ptr<kernel_siginfo> info, Ptr<task_struct> task, int group, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sock_exceed_buf_limit(Ptr<?> __data, Ptr<sock> sk,
      Ptr<proto> prot, long allocated, int kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_spi_transfer(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_swiotlb_bounced(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dev_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_sync_timeline(Ptr<?> __data,
      Ptr<sync_timeline> timeline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_task_newtask(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_task_rename($arg1, $arg2, (const u8 *)$arg3)")
  public static void do_trace_event_raw_event_task_rename(Ptr<?> __data, Ptr<task_struct> task,
      String comm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_ao_event($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void do_trace_event_raw_event_tcp_ao_event(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb, char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_ao_event_sk($arg1, (const struct sock *)$arg2, (const u8)$arg3, (const u8)$arg4)")
  public static void do_trace_event_raw_event_tcp_ao_event_sk(Ptr<?> __data, Ptr<sock> sk,
      char keyid, char rnext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_ao_event_sne($arg1, (const struct sock *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_tcp_ao_event_sne(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_event_skb($arg1, (const struct sk_buff *)$arg2)")
  public static void do_trace_event_raw_event_tcp_event_skb(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_hash_event($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void do_trace_event_raw_event_tcp_hash_event(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_probe($arg1, $arg2, (const struct sk_buff *)$arg3)")
  public static void do_trace_event_raw_event_tcp_probe(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_tcp_rcvbuf_grow(Ptr<?> __data, Ptr<sock> sk,
      int time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tcp_send_reset($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const enum sk_rst_reason)$arg4)")
  public static void do_trace_event_raw_event_tcp_send_reset(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb__nullable, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_thermal_power_devfreq_get_power(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, Ptr<devfreq_dev_status> status, @Unsigned long freq,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_thermal_power_devfreq_limit(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long freq, @Unsigned long cdev_state,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_thermal_temperature(Ptr<?> __data,
      Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_thermal_zone_trip(Ptr<?> __data,
      Ptr<thermal_zone_device> tz, int trip, thermal_trip_type trip_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_thread_noise(Ptr<?> __data, Ptr<task_struct> t,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tls_contenttype($arg1, (const struct sock *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_tls_contenttype(Ptr<?> __data, Ptr<sock> sk,
      char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_track_foreign_dirty(Ptr<?> __data, Ptr<folio> folio,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tsm_mr_read($arg1, (const struct tsm_measurement_register *)$arg2)")
  public static void do_trace_event_raw_event_tsm_mr_read(Ptr<?> __data,
      Ptr<tsm_measurement_register> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tsm_mr_refresh($arg1, (const struct tsm_measurement_register *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_tsm_mr_refresh(Ptr<?> __data,
      Ptr<tsm_measurement_register> mr, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_tsm_mr_write($arg1, (const struct tsm_measurement_register *)$arg2, (const u8 *)$arg3)")
  public static void do_trace_event_raw_event_tsm_mr_write(Ptr<?> __data,
      Ptr<tsm_measurement_register> mr, Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_udp_fail_queue_rcv_skb(Ptr<?> __data, int rc,
      Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_wakeup_source($arg1, (const u8 *)$arg2, $arg3)")
  public static void do_trace_event_raw_event_wakeup_source(Ptr<?> __data, String name,
      @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_wbc_class(Ptr<?> __data, Ptr<writeback_control> wbc,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_wbt_lat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned long lat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_wbt_stat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_wbt_step($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void do_trace_event_raw_event_wbt_step(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      String msg, int step, @Unsigned long window, @Unsigned int bg, @Unsigned int normal,
      @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_wbt_timer(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned int status, int step, @Unsigned int inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_workqueue_queue_work(Ptr<?> __data, int req_cpu,
      Ptr<pool_workqueue> pwq, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_bdi_register(Ptr<?> __data,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_class(Ptr<?> __data,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_dirty_inode_template(Ptr<?> __data,
      Ptr<inode> inode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_folio_template(Ptr<?> __data,
      Ptr<folio> folio, Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_queue_io(Ptr<?> __data,
      Ptr<bdi_writeback> wb, Ptr<wb_writeback_work> work, @Unsigned long dirtied_before,
      int moved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_sb_inodes_requeue(Ptr<?> __data,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_single_inode_template(Ptr<?> __data,
      Ptr<inode> inode, Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_work_class(Ptr<?> __data,
      Ptr<bdi_writeback> wb, Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_writeback_write_inode_template(Ptr<?> __data,
      Ptr<inode> inode, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_xen_mc_entry(Ptr<?> __data, Ptr<multicall_entry> mc,
      @Unsigned int nargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_event_raw_event_xen_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, $arg3, $arg4, $arg5)")
  public static void do_trace_event_raw_event_xen_mmu_flush_tlb_multi(Ptr<?> __data,
      Ptr<cpumask> cpus, Ptr<mm_struct> mm, @Unsigned long addr, @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_xhci_log_ctx(Ptr<?> __data, Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx, @Unsigned int ep_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_xhci_log_msg(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_event_raw_event_xhci_log_urb(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_netlink_extack((const u8 *)$arg1)")
  public static void do_trace_netlink_extack(String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_trace_rcu_torture_read((const u8 *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static void do_trace_rcu_torture_read(String rcutorturename, Ptr<callback_head> rhp,
      @Unsigned long secs, @Unsigned long c_old, @Unsigned long c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_rdpmc(@Unsigned int msr, @Unsigned long val, int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_read_msr(@Unsigned int msr, @Unsigned long val, int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trace_write_msr(@Unsigned int msr, @Unsigned long val, int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_trap(int trapnr, int signr, String str, Ptr<pt_regs> regs, long error_code,
      int sicode, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_truncate(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      @OriginalName("loff_t") long length, @Unsigned int time_attrs, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long do_try_to_free_pages(Ptr<zonelist> zonelist, Ptr<scan_control> sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_tty_hangup(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_umount(Ptr<mount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_unbind_con_driver((const struct consw *)$arg1, $arg2, $arg3, $arg4)")
  public static int do_unbind_con_driver(Ptr<consw> csw, int first, int last, int deflt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_unblank_screen(int leaving_gfx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_unexpected_cp(Ptr<pt_regs> regs, @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_unlinkat(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_unregister_con_driver((const struct consw *)$arg1)")
  public static int do_unregister_con_driver(Ptr<consw> csw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_update_region(Ptr<vc_data> vc, @Unsigned long start, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_user_addr_fault(Ptr<pt_regs> regs, @Unsigned long error_code,
      @Unsigned long address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_user_cp_fault(Ptr<pt_regs> regs, @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_utime(String filename, @OriginalName("time64_t") long mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_utimes($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static long do_utimes(int dfd, String filename, Ptr<timespec64> times, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_vc_no_ghcb(Ptr<pt_regs> regs, @Unsigned long exit_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_vfs_ioctl(Ptr<file> filp, @Unsigned int fd, @Unsigned int cmd,
      @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_vmi_align_munmap(Ptr<vma_iterator> vmi, Ptr<vm_area_struct> vma,
      Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long end, Ptr<list_head> uf,
      boolean unlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_vmi_munmap(Ptr<vma_iterator> vmi, Ptr<mm_struct> mm, @Unsigned long start,
      @Unsigned long len, Ptr<list_head> uf, boolean unlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long do_wait(Ptr<wait_opts> wo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_wait_intr(Ptr<@OriginalName("wait_queue_head_t") wait_queue_head> wq,
      Ptr<@OriginalName("wait_queue_entry_t") wait_queue_entry> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_wait_intr_irq(Ptr<@OriginalName("wait_queue_head_t") wait_queue_head> wq,
      Ptr<@OriginalName("wait_queue_entry_t") wait_queue_entry> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void do_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int do_wp_page(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int do_writepages(Ptr<address_space> mapping, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_writev($arg1, (const struct iovec *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long do_writev(@Unsigned long fd, Ptr<iovec> vec,
      @Unsigned long vlen, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("do_xdp_generic((const struct bpf_prog *)$arg1, $arg2)")
  public static int do_xdp_generic(Ptr<bpf_prog> xdp_prog, Ptr<Ptr<sk_buff>> pskb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct do_proc_dointvec_minmax_conv_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class do_proc_dointvec_minmax_conv_param extends Struct {
    public Ptr<java.lang.Integer> min;

    public Ptr<java.lang.Integer> max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct do_proc_douintvec_minmax_conv_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class do_proc_douintvec_minmax_conv_param extends Struct {
    public Ptr<java.lang. @Unsigned Integer> min;

    public Ptr<java.lang. @Unsigned Integer> max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct statfs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class statfs extends Struct {
    public @OriginalName("__kernel_long_t") long f_type;

    public @OriginalName("__kernel_long_t") long f_bsize;

    public @OriginalName("__kernel_long_t") long f_blocks;

    public @OriginalName("__kernel_long_t") long f_bfree;

    public @OriginalName("__kernel_long_t") long f_bavail;

    public @OriginalName("__kernel_long_t") long f_files;

    public @OriginalName("__kernel_long_t") long f_ffree;

    public __kernel_fsid_t f_fsid;

    public @OriginalName("__kernel_long_t") long f_namelen;

    public @OriginalName("__kernel_long_t") long f_frsize;

    public @OriginalName("__kernel_long_t") long f_flags;

    public @OriginalName("__kernel_long_t") long @Size(4) [] f_spare;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct statfs64"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class statfs64 extends Struct {
    public @OriginalName("__kernel_long_t") long f_type;

    public @OriginalName("__kernel_long_t") long f_bsize;

    public @Unsigned long f_blocks;

    public @Unsigned long f_bfree;

    public @Unsigned long f_bavail;

    public @Unsigned long f_files;

    public @Unsigned long f_ffree;

    public __kernel_fsid_t f_fsid;

    public @OriginalName("__kernel_long_t") long f_namelen;

    public @OriginalName("__kernel_long_t") long f_frsize;

    public @OriginalName("__kernel_long_t") long f_flags;

    public @OriginalName("__kernel_long_t") long @Size(4) [] f_spare;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct rlimit64"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class rlimit64 extends Struct {
    public @Unsigned long rlim_cur;

    public @Unsigned long rlim_max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ustat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ustat extends Struct {
    public @OriginalName("__kernel_daddr_t") int f_tfree;

    public @Unsigned long f_tinode;

    public char @Size(6) [] f_fname;

    public char @Size(6) [] f_fpack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tms"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tms extends Struct {
    public @OriginalName("__kernel_clock_t") long tms_utime;

    public @OriginalName("__kernel_clock_t") long tms_stime;

    public @OriginalName("__kernel_clock_t") long tms_cutime;

    public @OriginalName("__kernel_clock_t") long tms_cstime;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct klistmount"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class klistmount extends Struct {
    public @Unsigned long last_mnt_id;

    public @Unsigned long mnt_parent_id;

    public Ptr<java.lang. @Unsigned Long> kmnt_ids;

    public @Unsigned int nr_mnt_ids;

    public Ptr<mnt_namespace> ns;

    public path root;
  }
}
